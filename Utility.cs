#region Related components
using System;
using System.Linq;
using System.Net;
using System.IO;
using System.Data;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.StaticFiles;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.WebSockets;
using net.vieapps.Components.Security;
#endregion

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("VIEApps.Components.XUnitTests")]

namespace net.vieapps.Components.Utility
{
	/// <summary>
	/// Static servicing methods for working with ASP.NET Core
	/// </summary>
	public static partial class AspNetCoreUtilityService
	{
		/// <summary>
		/// Gets or Sets the name of server to write into headers
		/// </summary>
		public static string ServerName { get; set; } = "VIEApps NGX";

		internal static int BufferSize { get; } = 1024 * 16;

		internal static long SmallStreamLength { get; } = 1024 * 1024 * 2;

		#region Extensions for working with environments
		/// <summary>
		/// Gets max length of body request
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static long GetBodyRequestMaxLength(this HttpContext context)
		{
			var max = context.Features.Get<IHttpMaxRequestBodySizeFeature>().MaxRequestBodySize;
			return max != null
				? max.Value
				: Int64.MaxValue;
		}

		/// <summary>
		/// Gets the request ETag
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static string GetRequestETag(this HttpContext context)
		{
			// IE or common browser
			var requestETag = context.Request.Headers["If-Range"].First();

			// FireFox
			if (string.IsNullOrWhiteSpace(requestETag))
				requestETag = context.Request.Headers["If-Match"].First();

			// normalize
			if (!string.IsNullOrWhiteSpace(requestETag))
			{
				while (requestETag.StartsWith("\""))
					requestETag = requestETag.Right(requestETag.Length - 1);
				while (requestETag.EndsWith("\""))
					requestETag = requestETag.Left(requestETag.Length - 1);
			}

			// return the request ETag for resume downloading
			return requestETag;
		}

		/// <summary>
		/// Gets the approriate HTTP Status Code of the exception
		/// </summary>
		/// <param name="exception"></param>
		/// <returns></returns>
		public static int GetHttpStatusCode(this Exception exception)
		{
			if (exception is FileNotFoundException || exception is ServiceNotFoundException || exception is InformationNotFoundException)
				return (int)HttpStatusCode.NotFound;

			if (exception is AccessDeniedException)
				return (int)HttpStatusCode.Forbidden;

			if (exception is UnauthorizedException)
				return (int)HttpStatusCode.Unauthorized;

			if (exception is MethodNotAllowedException)
				return (int)HttpStatusCode.MethodNotAllowed;

			if (exception is InvalidRequestException)
				return (int)HttpStatusCode.BadRequest;

			if (exception is NotImplementedException)
				return (int)HttpStatusCode.NotImplemented;

			if (exception is ConnectionTimeoutException)
				return (int)HttpStatusCode.RequestTimeout;

			return (int)HttpStatusCode.InternalServerError;
		}

		/// <summary>
		/// Gets the name of server to write into headers
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static string GetServerName(this HttpContext context)
			=> string.IsNullOrWhiteSpace(AspNetCoreUtilityService.ServerName) ? "VIEApps NGX" : AspNetCoreUtilityService.ServerName;

		/// <summary>
		/// Gets the HTML body of a status code
		/// </summary>
		/// <param name="context"></param>
		/// <param name="statusCode"></param>
		/// <returns></returns>
		public static string GetHttpStatusCodeBody(this HttpContext context, int statusCode, string message = null, string type = null, string correlationID = null, string stack = null, bool showStack = true)
		{
			statusCode = statusCode < 1 ? (int)HttpStatusCode.InternalServerError : statusCode;
			var html = "<!DOCTYPE html>\r\n" +
				$"<html xmlns=\"http://www.w3.org/1999/xhtml\">\r\n" +
				$"<head>\r\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>\r\n<title>Error {statusCode}</title>\r\n</head>\r\n<body>\r\n" +
				$"<h1>HTTP {statusCode}{(string.IsNullOrWhiteSpace(message) ? "" : $" - {message.Replace("<", "&lt;").Replace(">", "&gt;")}")}</h1>\r\n";
			if (!string.IsNullOrWhiteSpace(type))
				html += $"<hr/>\r\n<div>Type: {type}</div>\r\n";
			if (!string.IsNullOrWhiteSpace(stack) && showStack)
				html += $"<div>Stack:</div>\r\n<blockquote>{stack.Replace("<", "&lt;").Replace(">", "&gt;").Replace("\n", "<br/>").Replace("\r", "").Replace("\t", "")}</blockquote>\r\n";
			html += $"<hr/>\r\n"
				+ $"<div> {(!string.IsNullOrWhiteSpace(correlationID) ? $"Correlation ID: {correlationID} - " : "")}"
				+ $"Powered by {context.GetServerName()} v{Assembly.GetExecutingAssembly().GetVersion(false)}</div>\r\n"
				+ "</body>\r\n</html>";
			return html;
		}

		static FileExtensionContentTypeProvider MimeTypeProvider { get; set; }

		/// <summary>
		/// Gets the MIME type of a file
		/// </summary>
		/// <param name="filename"></param>
		/// <returns></returns>
		public static string GetMimeType(this string filename)
			=> (AspNetCoreUtilityService.MimeTypeProvider ?? (AspNetCoreUtilityService.MimeTypeProvider = new FileExtensionContentTypeProvider())).TryGetContentType(filename, out string mimeType)
				? mimeType
				: "application/octet-stream";

		/// <summary>
		/// Gets the MIME type of a file
		/// </summary>
		/// <param name="fileInfo"></param>
		/// <returns></returns>
		public static string GetMimeType(this FileInfo fileInfo)
			=> fileInfo.Name.GetMimeType();

		/// <summary>
		/// Parses the query of an uri
		/// </summary>
		/// <param name="uri"></param>
		/// /// <param name="onCompleted">Action to run on parsing completed</param>
		/// <returns>The collection of key and value pair</returns>
		public static Dictionary<string, string> ParseQuery(this Uri uri, Action<Dictionary<string, string>> onCompleted = null)
		{
			var query = QueryHelpers.ParseQuery(uri.Query).ToDictionary(kvp => kvp.Key, kvp => kvp.Value.ToString(), StringComparer.OrdinalIgnoreCase);
			onCompleted?.Invoke(query);
			return query;
		}

		/// <summary>
		/// Parses the query of the request in this context
		/// </summary>
		/// <param name="context"></param>
		/// /// <param name="onCompleted">Action to run on parsing completed</param>
		/// <returns>The collection of key and value pair</returns>
		public static Dictionary<string, string> ParseQuery(this HttpContext context, Action<Dictionary<string, string>> onCompleted = null)
			=> context.GetRequestUri().ParseQuery(onCompleted);

		/// <summary>
		/// Gets the value of a header parameter
		/// </summary>
		/// <param name="context"></param>
		/// <param name="name">The string that presents name of parameter want to get</param>
		/// <returns></returns>
		public static string GetHeaderParameter(this HttpContext context, string name)
		{
			var value = string.IsNullOrWhiteSpace(name) ? string.Empty : context.Request.Headers[name].ToString();
			return string.IsNullOrWhiteSpace(value) ? null : value;
		}

		/// <summary>
		/// Gets the value of a query parameter
		/// </summary>
		/// <param name="context"></param>
		/// <param name="name">The string that presents name of parameter want to get</param>
		/// <returns></returns>
		public static string GetQueryParameter(this HttpContext context, string name)
			=> !string.IsNullOrWhiteSpace(name)
				? context.Request.QueryString.ToDictionary().TryGetValue(name, out string value)
					? value
					: null
				: null;

		/// <summary>
		/// Gets the value of a parameter (first from header, if not found then get from query string)
		/// </summary>
		/// <param name="context"></param>
		/// <param name="name">The string that presents name of parameter want to get</param>
		/// <returns></returns>
		public static string GetParameter(this HttpContext context, string name)
			=> context.GetHeaderParameter(name) ?? context.GetQueryParameter(name);

		/// <summary>
		/// Gets the original Uniform Resource Identifier (URI) of the request that was sent by the client
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static Uri GetUri(this HttpContext context)
			=> new Uri($"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}{context.Request.Path}{context.Request.QueryString}");

		/// <summary>
		/// Gets the original Uniform Resource Identifier (URI) of the request that was sent by the client
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static Uri GetRequestUri(this HttpContext context)
			=> context.GetUri();

		/// <summary>
		/// Gets the url of current uri that not include query-string
		/// </summary>
		/// <param name="uri"></param>
		/// <param name="toLower"></param>
		/// <param name="useRelativeUrl"></param>
		/// <returns></returns>
		public static string GetUrl(this Uri uri, bool toLower = false, bool useRelativeUrl = false)
		{
			var url = useRelativeUrl ? uri.PathAndQuery : uri.ToString();
			url = toLower ? url.ToLower() : url;
			var pos = url.IndexOf("?");
			return pos > 0 ? url.Left(pos) : url;
		}

		/// <summary>
		/// Gets the url of current request (query-string is excluded)
		/// </summary>
		/// <param name="context"></param>
		/// <param name="toLower"></param>
		/// <param name="useRelativeUrl"></param>
		/// <returns></returns>
		public static string GetRequestUrl(this HttpContext context, bool toLower = false, bool useRelativeUrl = false)
			=> context.GetRequestUri().GetUrl(toLower, useRelativeUrl);

		/// <summary>
		/// Gets the host url (scheme, host and port - if not equals to default)
		/// </summary>
		/// <param name="uri"></param>
		/// <returns></returns>
		public static string GetHostUrl(this Uri uri)
			=> uri.Scheme + "://" + uri.Host + (uri.Port != 80 && uri.Port != 443 ? $":{uri.Port}" : "");

		/// <summary>
		/// Gets the host url (scheme, host and port - if not equals to default)
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static string GetHostUrl(this HttpContext context)
			=> context.GetRequestUri().GetHostUrl();

		/// <summary>
		/// Gets path segments of this uri
		/// </summary>
		/// <param name="uri"></param>
		/// <param name="toLower"></param>
		/// <returns></returns>
		public static string[] GetRequestPathSegments(this Uri uri, bool toLower = false)
		{
			var path = uri.GetUrl(toLower, true);
			return path.Equals("/") || path.Equals("~/")
				? new[] { "" }
				: path.ToArray('/', true);
		}

		/// <summary>
		/// Gets path segments of this request
		/// </summary>
		/// <param name="context"></param>
		/// <param name="toLower"></param>
		/// <returns></returns>
		public static string[] GetRequestPathSegments(this HttpContext context, bool toLower = false)
			=> context.GetRequestUri().GetRequestPathSegments(toLower);

		/// <summary>
		/// Gets the refer Uniform Resource Identifier (URI) of the request that was sent by the client
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static Uri GetReferUri(this HttpContext context)
		{
			var referer = context.Request.Headers["Referer"].ToString();
			return string.IsNullOrWhiteSpace(referer) ? null : new Uri(referer);
		}

		/// <summary>
		/// Gets the origin Uniform Resource Identifier (URI) of the request that was sent by the client
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static Uri GetOriginUri(this HttpContext context)
		{
			var origin = context.Request.Headers["Origin"].ToString();
			return string.IsNullOrWhiteSpace(origin) ? null : new Uri(origin);
		}

		/// <summary>
		/// Gets the user-agent string of the request that was sent by the client
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static string GetUserAgent(this HttpContext context)
		{
			var userAgent = context.Request.Headers["User-Agent"].ToString();
			return string.IsNullOrWhiteSpace(userAgent) ? "" : userAgent;
		}

		/// <summary>
		/// Gets the local endpoint
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static IPEndPoint GetLocalEndPoint(this HttpContext context)
			=> new IPEndPoint(context.Connection.LocalIpAddress, context.Connection.LocalPort);

		/// <summary>
		/// Gets the remote endpoint
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static IPEndPoint GetRemoteEndPoint(this HttpContext context)
		{
			var endpoint = new IPEndPoint(context.Connection.RemoteIpAddress, context.Connection.RemotePort);
			if (endpoint.Port == 0)
				try
				{
					var uri = !string.IsNullOrWhiteSpace(context.Request.Headers["x-original-remote-endpoint"])
						? new Uri($"https://{context.Request.Headers["x-original-remote-endpoint"]}")
						: !string.IsNullOrWhiteSpace(context.Request.Headers["cf-connecting-ip"])
							? new Uri($"https://{context.Request.Headers["cf-connecting-ip"]}:{new Uri($"https://{context.Request.Headers["x-original-for"]}").Port}")
							: new Uri($"https://{context.Request.Headers["x-original-for"]}");
					endpoint = new IPEndPoint(IPAddress.Parse(uri.Host), uri.Port);
				}
				catch { }
			return endpoint;
		}
		#endregion

		#region Set responses' headers
		/// <summary>
		/// Sets the approriate headers of response
		/// </summary>
		/// <param name="context"></param>
		/// <param name="statusCode">The HTTP status code</param>
		/// <param name="headers">The HTTP headers</param>
		/// <param name="tryWriteEmptyResponse">true to try to write empty response</param>
		public static void SetResponseHeaders(this HttpContext context, int statusCode, Dictionary<string, string> headers = null, bool tryWriteEmptyResponse = false)
		{
			context.Response.StatusCode = statusCode;

			headers?.ForEach(kvp => context.Response.Headers[kvp.Key] = kvp.Value);
			context.Response.Headers["Server"] = context.GetServerName();
			if (context.Items.ContainsKey("PipelineStopwatch") && context.Items["PipelineStopwatch"] is Stopwatch stopwatch)
			{
				stopwatch.Stop();
				context.Response.Headers["X-Execution-Times"] = stopwatch.GetElapsedTimes();
			}

			if (tryWriteEmptyResponse)
				context.Write(new byte[0]);
		}

		/// <summary>
		/// Sets the approriate headers of response
		/// </summary>
		/// <param name="context"></param>
		/// <param name="statusCode">The HTTP status code</param>
		/// <param name="contentType">The MIME content type</param>
		/// <param name="eTag">The entity tag</param>
		/// <param name="lastModified">The number that presents Unix timestamp</param>
		/// <param name="correlationID">The correlation idenntity</param>
		/// <param name="headers">The additional headers</param>
		public static void SetResponseHeaders(this HttpContext context, int statusCode, string contentType, string eTag, long lastModified, string cacheControl, TimeSpan expires, string correlationID = null, Dictionary<string, string> headers = null)
		{
			// prepare
			headers = new Dictionary<string, string>(headers ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase);

			if (!string.IsNullOrWhiteSpace(contentType))
				headers["Content-Type"] = $"{contentType}{(contentType.IsEndsWith("; charset=utf-8") ? "" : "; charset=utf-8")}";

			if (!string.IsNullOrWhiteSpace(eTag))
				headers["ETag"] = eTag;

			if (lastModified > 0)
				headers["Last-Modified"] = lastModified.FromUnixTimestamp().ToHttpString();

			if (!string.IsNullOrWhiteSpace(cacheControl))
			{
				headers["Cache-Control"] = cacheControl;
				if (expires != default(TimeSpan) && expires.Ticks > 0)
					headers["Expires"] = DateTime.Now.Add(expires).ToHttpString();
			}

			if (!string.IsNullOrWhiteSpace(correlationID))
				headers["X-Correlation-ID"] = correlationID;

			// update
			context.SetResponseHeaders(statusCode, headers);
		}

		/// <summary>
		/// Set response headers with special status code for using with StatusCodeHandler (UseStatusCodePages middleware)
		/// </summary>
		/// <param name="context"></param>
		/// <param name="statusCode"></param>
		/// <param name="eTag"></param>
		/// <param name="lastModified"></param>
		/// <param name="cacheControl"></param>
		/// <param name="correlationID"></param>
		/// <param name="headers"></param>
		public static void SetResponseHeaders(this HttpContext context, int statusCode, string eTag, long lastModified, string cacheControl, string correlationID, Dictionary<string, string> headers = null)
		{
			// prepare headers
			headers = new Dictionary<string, string>(headers ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase);

			if (!string.IsNullOrWhiteSpace(eTag))
				headers["ETag"] = eTag;

			if (!string.IsNullOrWhiteSpace(correlationID))
				headers["X-Correlation-ID"] = correlationID;

			if (lastModified > 0)
				headers["Last-Modified"] = lastModified.FromUnixTimestamp().ToHttpString();

			// update into context to use at status page middleware
			context.Items["StatusCode"] = statusCode;
			context.Items["Body"] = "";
			context.Items["Headers"] = headers;
			if (cacheControl != null)
				context.Items["CacheControl"] = cacheControl;

			// update
			context.SetResponseHeaders(statusCode, headers);
		}
		#endregion

		#region Flush & Redirect response
		/// <summary>
		/// Sends all currently buffered output to the client
		/// </summary>
		/// <param name="context"></param>
		public static void Flush(this HttpContext context)
			=> context.Response.Body.Flush();

		/// <summary>
		/// Asynchronously sends all currently buffered output to the client
		/// </summary>
		/// <param name="context"></param>
		/// <param name="cancellationToken"></param>
		public static async Task FlushAsync(this HttpContext context, CancellationToken cancellationToken = default(CancellationToken))
		{
			using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, context.RequestAborted))
			{
				await context.Response.Body.FlushAsync(cts.Token).ConfigureAwait(false);
			}
		}

		/// <summary>
		/// Redirects the response by send the redirect status code (301 or 302) to client
		/// </summary>
		/// <param name="context"></param>
		/// <param name="location">The location to redirect to - must be encoded</param>
		/// <param name="redirectPermanently">true to use 301 (Moved Permanently) instead of 302 (Redirect Temporary)</param>
		public static void Redirect(this HttpContext context, string location, bool redirectPermanently = false)
		{
			if (string.IsNullOrWhiteSpace(location))
				return;

			var uri = new Uri(location);
			var segments = uri.GetRequestPathSegments();
			var path = "/" + segments.Select(segment => segment.UrlDecode().UrlEncode()).Join("/") + (segments.Length > 0 && location.EndsWith("/") ? "/" : "");
			var query = uri.ParseQuery().Select(kvp => kvp.Key + "=" + kvp.Value.UrlDecode().UrlEncode()).Join("&");

			context.SetResponseHeaders(
				redirectPermanently ? (int)HttpStatusCode.MovedPermanently : (int)HttpStatusCode.Redirect,
				new Dictionary<string, string>
				{
					{ "Location", uri.Scheme + "://" + uri.Host + (uri.Port != 80 && uri.Port != 443 ? $":{uri.Port}" : "") + path + (string.IsNullOrWhiteSpace(query) ? "" : "?" + query) }
				},
				true
			);
		}

		/// <summary>
		/// Redirects permanently the response by send the status code (301 - MovedPermanently) to client
		/// </summary>
		/// <param name="context"></param>
		/// <param name="location"></param>
		public static void RedirectPermanently(this HttpContext context, string location)
			=> context.Redirect(location, true);
		#endregion

		#region Read data from request
		/// <summary>
		/// Reads data from request body
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static byte[] Read(this HttpContext context)
		{
			var data = new byte[0];
			var buffer = new byte[TextFileReader.BufferSize];
			var read = context.Request.Body.Read(buffer, 0, buffer.Length);
			while (read > 0)
			{
				data = data.Concat(buffer.Take(0, read));
				read = context.Request.Body.Read(buffer, 0, buffer.Length);
			}
			return data;
		}

		/// <summary>
		/// Reads data from request body
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static async Task<byte[]> ReadAsync(this HttpContext context, CancellationToken cancellationToken = default(CancellationToken))
		{
			var data = new byte[0];
			var buffer = new byte[TextFileReader.BufferSize];
			var read = await context.Request.Body.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
			while (read > 0)
			{
				data = data.Concat(buffer.Take(0, read));
				read = await context.Request.Body.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
			}
			return data;
		}

		/// <summary>
		/// Reads data as text from request body
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static string ReadText(this HttpContext context)
		{
			using (var reader = new StreamReader(context.Request.Body))
			{
				return reader.ReadToEnd();
			}
		}

		/// <summary>
		/// Reads data as text from request body
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static async Task<string> ReadTextAsync(this HttpContext context, CancellationToken cancellationToken = default(CancellationToken))
		{
			using (var reader = new StreamReader(context.Request.Body))
			{
				return await reader.ReadToEndAsync().WithCancellationToken(cancellationToken).ConfigureAwait(false);
			}
		}
		#endregion

		#region Write binary data to the response body
		/// <summary>
		/// Writes binary data to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="buffer"></param>
		/// <param name="offset"></param>
		/// <param name="count"></param>
		public static void Write(this HttpContext context, byte[] buffer, int offset = 0, int count = 0) 
			=> context.Response.Body.Write(buffer, offset > -1 ? offset : 0, count > 0 ? count : buffer.Length);

		/// <summary>
		/// Writes binary data to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="buffer"></param>
		/// <returns></returns>
		public static void Write(this HttpContext context, ArraySegment<byte> buffer) 
			=> context.Response.Body.Write(buffer.Array, buffer.Offset, buffer.Count);

		/// <summary>
		/// Writes binary data to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="buffer"></param>
		/// <param name="offset"></param>
		/// <param name="count"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static async Task WriteAsync(this HttpContext context, byte[] buffer, int offset = 0, int count = 0, CancellationToken cancellationToken = default(CancellationToken))
		{
			using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, context.RequestAborted))
			{
				await context.Response.Body.WriteAsync(buffer, offset > -1 ? offset : 0, count > 0 ? count : buffer.Length, cts.Token).ConfigureAwait(false);
			}
		}

		/// <summary>
		/// Writes binary data to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="buffer"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, byte[] buffer, CancellationToken cancellationToken)
			=> context.WriteAsync(buffer, 0, 0, cancellationToken);

		/// <summary>
		/// Writes binary data to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="buffer"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, ArraySegment<byte> buffer, CancellationToken cancellationToken = default(CancellationToken))
			=> context.WriteAsync(buffer.Array, buffer.Offset, buffer.Count, cancellationToken);

		/// <summary>
		/// Writes the stream to the output response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="stream">The stream to write</param>
		/// <param name="headers">The headers</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static async Task WriteAsync(this HttpContext context, Stream stream, Dictionary<string, string> headers, CancellationToken cancellationToken = default(CancellationToken))
		{
			// check ETag for supporting resumeable downloaders
			var eTag = headers != null && headers.ContainsKey("ETag") ? headers["ETag"] : null;
			if (!string.IsNullOrWhiteSpace(eTag))
			{
				var requestETag = context.GetRequestETag();
				if (!string.IsNullOrWhiteSpace(requestETag) && !eTag.Equals(requestETag))
				{
					context.SetResponseHeaders((int)HttpStatusCode.PreconditionFailed, null, 0, "private", null);
					return;
				}
			}

			// prepare position for flushing as partial blocks
			var flushAsPartialContent = false;
			var totalBytes = stream.Length;
			long startBytes = 0, endBytes = totalBytes - 1;
			if (!string.IsNullOrWhiteSpace(context.Request.Headers["Range"].First()))
			{
				var requestedRange = context.Request.Headers["Range"].First();
				var range = requestedRange.Split(new[] { '=', '-' });

				startBytes = range[1].CastAs<long>();
				if (startBytes >= totalBytes)
				{
					context.SetResponseHeaders((int)HttpStatusCode.PreconditionFailed, null, 0, "private", null);
					return;
				}

				flushAsPartialContent = true;

				if (startBytes < 0)
					startBytes = 0;

				try
				{
					endBytes = range[2].CastAs<long>();
				}
				catch { }

				if (endBytes > totalBytes - 1)
					endBytes = totalBytes - 1;
			}

			// update headers
			headers = new Dictionary<string, string>(headers ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
			{
				{ "Content-Length", $"{(endBytes - startBytes) + 1}" },
			};

			if (flushAsPartialContent && startBytes > -1)
				headers["Content-Range"] = $"bytes {startBytes}-{endBytes}/{totalBytes}";

			if (!string.IsNullOrWhiteSpace(eTag))
				headers["Accept-Ranges"] = "bytes";

			try
			{
				context.SetResponseHeaders(flushAsPartialContent ? (int)HttpStatusCode.PartialContent : (int)HttpStatusCode.OK, headers, context.Request.Method.IsEquals("HEAD"));
				await context.FlushAsync(cancellationToken).ConfigureAwait(false);
				if (context.Request.Method.IsEquals("HEAD"))
					return;
			}
			catch (OperationCanceledException)
			{
				return;
			}
			catch (Exception)
			{
				throw;
			}

			// write small stream
			if (!flushAsPartialContent && totalBytes <= AspNetCoreUtilityService.SmallStreamLength)
				try
				{
					using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, context.RequestAborted))
					{
						await stream.CopyToAsync(context.Response.Body, AspNetCoreUtilityService.BufferSize, cts.Token).ConfigureAwait(false);
					}
				}
				catch (OperationCanceledException)
				{
					return;
				}
				catch (Exception)
				{
					throw;
				}

			// write large stream
			else
			{
				// jump to requested position
				stream.Seek(startBytes > 0 ? startBytes : 0, SeekOrigin.Begin);

				// read and flush stream data to response stream
				var size = AspNetCoreUtilityService.BufferSize;
				if (size > (endBytes - startBytes))
					size = (int)(endBytes - startBytes) + 1;

				var buffer = new byte[size];
				var total = (int)Math.Ceiling((endBytes - startBytes + 0.0) / size);
				var count = 0;

				while (count < total)
					try
					{
						var read = await stream.ReadAsync(buffer, 0, size, cancellationToken).ConfigureAwait(false);
						if (read > 0)
						{
							await context.WriteAsync(buffer, 0, read, cancellationToken).ConfigureAwait(false);
							await context.FlushAsync(cancellationToken).ConfigureAwait(false);
						}
						count++;
					}
					catch (OperationCanceledException)
					{
						return;
					}
					catch (Exception)
					{
						throw;
					}
			}
		}

		/// <summary>
		/// Writes the stream to the output response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="stream">The stream to write</param>
		/// <param name="contentType">The MIME type</param>
		/// <param name="contentDisposition">The string that presents name of attachment file, let it empty/null for writting showing/displaying (not for downloading attachment file)</param>
		/// <param name="eTag">The entity tag</param>
		/// <param name="lastModified">The Unix timestamp that presents last-modified time</param>
		/// <param name="cacheControl">The string that presents cache control ('public', 'private', 'no-store')</param>
		/// <param name="expires">The timespan that presents expires time of cache</param>
		/// <param name="headers">The additional headers</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, Stream stream, string contentType, string contentDisposition = null, string eTag = null, long lastModified = 0, string cacheControl = null, TimeSpan expires = default(TimeSpan), Dictionary<string, string> headers = null, string correlationID = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			// prepare headers
			headers = new Dictionary<string, string>(headers ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase);

			if (!string.IsNullOrWhiteSpace(contentType))
				headers["Content-Type"] = $"{contentType}{(contentType.IsEndsWith("; charset=utf-8") ? "" : "; charset=utf-8")}";

			if (!string.IsNullOrWhiteSpace(contentDisposition))
				headers["Content-Disposition"] = $"Attachment; Filename=\"{contentDisposition.UrlEncode()}\"";

			if (!string.IsNullOrWhiteSpace(eTag))
				headers["ETag"] = eTag;

			if (lastModified > 0)
				headers["Last-Modified"] = lastModified.FromUnixTimestamp().ToHttpString();

			if (!string.IsNullOrWhiteSpace(cacheControl))
			{
				headers["Cache-Control"] = cacheControl;
				if (expires != default(TimeSpan) && expires.Ticks > 0)
					headers["Expires"] = DateTime.Now.Add(expires).ToHttpString();
			}

			if (!string.IsNullOrWhiteSpace(correlationID))
				headers["X-Correlation-ID"] = correlationID;

			// write
			return context.WriteAsync(stream, headers, cancellationToken);
		}

		/// <summary>
		/// Writes the stream to the output response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="stream">The stream to write</param>
		/// <param name="contentType">The MIME type</param>
		/// <param name="contentDisposition">The string that presents name of attachment file, let it empty/null for writting showing/displaying (not for downloading attachment file)</param>
		/// <param name="eTag">The entity tag</param>
		/// <param name="lastModified">The Unix timestamp that presents last-modified time</param>
		/// <param name="cacheControl">The string that presents cache control ('public', 'private', 'no-store')</param>
		/// <param name="expires">The timespan that presents expires time of cache</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, Stream stream, string contentType, string contentDisposition, string eTag, long lastModified, string cacheControl, TimeSpan expires, CancellationToken cancellationToken = default(CancellationToken))
			=> context.WriteAsync(stream, contentType, contentDisposition, eTag, lastModified, cacheControl, expires, null, null, cancellationToken);

		/// <summary>
		/// Writes binary data to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="buffer">The data to write</param>
		/// <param name="contentType">The MIME type</param>
		/// <param name="contentDisposition">The string that presents name of attachment file, let it empty/null for writting showing/displaying (not for downloading attachment file)</param>
		/// <param name="eTag">The entity tag</param>
		/// <param name="lastModified">The Unix timestamp that presents last-modified time</param>
		/// <param name="cacheControl">The string that presents cache control ('public', 'private', 'no-store')</param>
		/// <param name="expires">The timespan that presents expires time of cache</param>
		/// <param name="headers">The additional headers</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static async Task WriteAsync(this HttpContext context, byte[] buffer, string contentType, string contentDisposition = null, string eTag = null, long lastModified = 0, string cacheControl = null, TimeSpan expires = default(TimeSpan), Dictionary<string, string> headers = null, string correlationID = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			using (var stream = buffer.ToMemoryStream())
			{
				await context.WriteAsync(stream, contentType, contentDisposition, eTag, lastModified, cacheControl, expires, headers, correlationID, cancellationToken).ConfigureAwait(false);
			}
		}

		/// <summary>
		/// Writes binary data to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="buffer">The data to write</param>
		/// <param name="contentType">The MIME type</param>
		/// <param name="contentDisposition">The string that presents name of attachment file, let it empty/null for writting showing/displaying (not for downloading attachment file)</param>
		/// <param name="eTag">The entity tag</param>
		/// <param name="lastModified">The Unix timestamp that presents last-modified time</param>
		/// <param name="cacheControl">The string that presents cache control ('public', 'private', 'no-store')</param>
		/// <param name="expires">The timespan that presents expires time of cache</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, byte[] buffer, string contentType, string contentDisposition, string eTag, long lastModified, string cacheControl, TimeSpan expires, CancellationToken cancellationToken = default(CancellationToken))
			=> context.WriteAsync(buffer, contentType, contentDisposition, eTag, lastModified, cacheControl, expires, null, null, cancellationToken);

		/// <summary>
		/// Writes the content of a file (binary) to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="fileInfo">The information of the file</param>
		/// <param name="contentType">The MIME type</param>
		/// <param name="contentDisposition">The string that presents name of attachment file, let it empty/null for writting showing/displaying (not for downloading attachment file)</param>
		/// <param name="eTag">The entity tag</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static async Task WriteAsync(this HttpContext context, FileInfo fileInfo, string contentType, string contentDisposition = null, string eTag = null, string correlationID = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			if (fileInfo == null || !fileInfo.Exists)
				throw new FileNotFoundException("Not found" + (fileInfo != null ? " [" + fileInfo.Name + "]" : ""));

			using (var stream = new FileStream(fileInfo.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, TextFileReader.BufferSize, true))
			{
				await context.WriteAsync(stream, contentType, contentDisposition, eTag, fileInfo.LastWriteTime.ToUnixTimestamp(), "public", TimeSpan.FromDays(7), null, correlationID, cancellationToken).ConfigureAwait(false);
			}
		}

		/// <summary>
		/// Writes the content of a file (binary) to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="fileInfo">The information of the file</param>
		/// <param name="contentType">The MIME type</param>
		/// <param name="contentDisposition">The string that presents name of attachment file, let it empty/null for writting showing/displaying (not for downloading attachment file)</param>
		/// <param name="eTag">The entity tag</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, FileInfo fileInfo, string contentType, string contentDisposition, string eTag = null, CancellationToken cancellationToken = default(CancellationToken))
			=> context.WriteAsync(fileInfo, contentType, contentDisposition, eTag,null, cancellationToken);
		#endregion

		#region Write a data-set as Excel document to the response body
		/// <summary>
		/// Writes a data-set as Excel document to to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="dataSet"></param>
		/// <param name="filename"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static async Task WriteAsExcelDocumentAsync(this HttpContext context, DataSet dataSet, string filename = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			using (var stream = await dataSet.SaveAsExcelAsync(cancellationToken).ConfigureAwait(false))
			{
				await context.WriteAsync(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", filename = filename ?? dataSet.Tables[0].TableName + ".xlsx", null, 0, null, default(TimeSpan), null, null, cancellationToken).ConfigureAwait(false);
			}
		}

		/// <summary>
		/// Writes a data-set as Excel document to HTTP output stream directly
		/// </summary>
		/// <param name="context"></param>
		/// <param name="dataSet"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsExcelDocumentAsync(this HttpContext context, DataSet dataSet, CancellationToken cancellationToken = default(CancellationToken)) 
			=> context.WriteAsExcelDocumentAsync(dataSet, null, cancellationToken);
		#endregion

		#region Write text data to the response body
		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="encoding"></param>
		public static void Write(this HttpContext context, string text, Encoding encoding = null) => context.Write(text.ToBytes(encoding));

		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="encoding"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, string text, Encoding encoding = null, CancellationToken cancellationToken = default(CancellationToken)) 
			=> context.WriteAsync(text.ToBytes(encoding).ToArraySegment(), cancellationToken);

		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, string text, CancellationToken cancellationToken) 
			=> context.WriteAsync(text.ToBytes().ToArraySegment(), cancellationToken);

		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="contentType"></param>
		/// <param name="eTag"></param>
		/// <param name="lastModified"></param>
		/// <param name="cacheControl"></param>
		/// <param name="expires"></param>
		/// <param name="correlationID"></param>
		public static void Write(this HttpContext context, string text, string contentType, string eTag, long lastModified, string cacheControl, TimeSpan expires, string correlationID = null)
		{
			context.SetResponseHeaders((int)HttpStatusCode.OK, contentType, eTag, lastModified, cacheControl, expires, correlationID);
			context.Write(text.ToBytes());
		}

		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="contentType"></param>
		/// <param name="correlationID"></param>
		public static void Write(this HttpContext context, string text, string contentType = "text/html", string correlationID = null) 
			=> context.Write(text, contentType, null, 0, null, default(TimeSpan), correlationID);

		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="contentType"></param>
		/// <param name="eTag"></param>
		/// <param name="lastModified"></param>
		/// <param name="cacheControl"></param>
		/// <param name="expires"></param>
		/// <param name="correlationID"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static async Task WriteAsync(this HttpContext context, string text, string contentType, string eTag, long lastModified, string cacheControl, TimeSpan expires, string correlationID = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			context.SetResponseHeaders((int)HttpStatusCode.OK, contentType, eTag, lastModified, cacheControl, expires, correlationID);
			await context.WriteAsync(text.ToBytes().ToArraySegment(), cancellationToken).ConfigureAwait(false);
		}

		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="contentType"></param>
		/// <param name="correlationID"></param>
		public static Task WriteAsync(this HttpContext context, string text, string contentType = "text/html", string correlationID = null, CancellationToken cancellationToken = default(CancellationToken))
			=> context.WriteAsync(text, contentType, null, 0, null, default(TimeSpan), correlationID);
		#endregion

		#region Write JSON data to the response body
		/// <summary>
		/// Writes the JSON to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="json"></param>
		/// <param name="formatting"></param>
		/// <param name="eTag"></param>
		/// <param name="lastModified"></param>
		/// <param name="cacheControl"></param>
		/// <param name="expires"></param>
		/// <param name="correlationID"></param>
		public static void Write(this HttpContext context, JToken json, Formatting formatting, string eTag, long lastModified, string cacheControl, TimeSpan expires, string correlationID = null)
			=> context.Write(json?.ToString(formatting) ?? "{}", "application/json", eTag, lastModified, cacheControl, expires, correlationID);

		/// <summary>
		/// Writes the JSON to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="json"></param>
		/// <param name="formatting"></param>
		/// <param name="correlationID"></param>
		public static void Write(this HttpContext context, JToken json, Formatting formatting = Formatting.None, string correlationID = null) 
			=> context.Write(json, formatting, null, 0, null, default(TimeSpan), correlationID);

		/// <summary>
		/// Writes the JSON to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="json"></param>
		/// <param name="formatting"></param>
		/// <param name="eTag"></param>
		/// <param name="lastModified"></param>
		/// <param name="cacheControl"></param>
		/// <param name="expires"></param>
		/// <param name="correlationID"></param>
		public static Task WriteAsync(this HttpContext context, JToken json, Formatting formatting, string eTag, long lastModified, string cacheControl, TimeSpan expires, string correlationID = null, CancellationToken cancellationToken = default(CancellationToken))
			=> context.WriteAsync(json?.ToString(formatting) ?? "{}", "application/json", eTag, lastModified, cacheControl, expires, correlationID, cancellationToken);

		/// <summary>
		/// Writes the JSON to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="json"></param>
		/// <param name="formatting"></param>
		/// <param name="correlationID"></param>
		public static Task WriteAsync(this HttpContext context, JToken json, Formatting formatting = Formatting.None, string correlationID = null, CancellationToken cancellationToken = default(CancellationToken))
			=> context.WriteAsync(json, formatting, null, 0, null, default(TimeSpan), correlationID, cancellationToken);

		/// <summary>
		/// Writes the JSON to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="json"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, JToken json, CancellationToken cancellationToken) 
			=> context.WriteAsync(json, Formatting.None, null, cancellationToken);
		#endregion

		#region Show HTTP error as HTML
		/// <summary>
		/// Shows HTTP error as HTML
		/// </summary>
		/// <param name="context"></param>
		/// <param name="statusCode"></param>
		/// <param name="message"></param>
		/// <param name="type"></param>
		/// <param name="correlationID"></param>
		/// <param name="stack"></param>
		/// <param name="showStack"></param>
		public static void ShowHttpError(this HttpContext context, int statusCode, string message, string type, string correlationID = null, string stack = null, bool showStack = true)
		{
			// update into context to use at status page middleware
			statusCode = statusCode < 1 ? (int)HttpStatusCode.InternalServerError : statusCode;
			context.Items["StatusCode"] = statusCode;
			context.Items["ContentType"] = "text/html";
			context.Items["Body"] = context.GetHttpStatusCodeBody(statusCode, message, type, correlationID, stack, showStack);

			// set status code to raise status page middleware
			context.Response.StatusCode = statusCode;
		}

		/// <summary>
		/// Shows HTTP error as HTML
		/// </summary>
		/// <param name="context"></param>
		/// <param name="statusCode"></param>
		/// <param name="message"></param>
		/// <param name="type"></param>
		/// <param name="correlationID"></param>
		/// <param name="ex"></param>
		/// <param name="showStack"></param>
		public static void ShowHttpError(this HttpContext context, int statusCode, string message, string type, string correlationID, Exception ex, bool showStack = true)
		{
			var stack = string.Empty;
			if (ex != null && showStack)
			{
				stack = ex.StackTrace;
				var counter = 1;
				var inner = ex.InnerException;
				while (inner != null)
				{
					stack += "\r\n" + $" ---- Inner [{counter}] -------------------------------------- " + "\r\n" + inner.StackTrace;
					inner = inner.InnerException;
					counter++;
				}
			}
			context.ShowHttpError(statusCode, message, type, correlationID, stack, showStack);
		}
		#endregion

		#region Write HTTP error as JSON
		/// <summary>
		/// Writes HTTP error as JSON
		/// </summary>
		/// <param name="context"></param>
		/// <param name="statusCode"></param>
		/// <param name="message"></param>
		/// <param name="type"></param>
		/// <param name="correlationID"></param>
		/// <param name="stack"></param>
		public static void WriteHttpError(this HttpContext context, int statusCode, string message, string type, string correlationID = null, JArray stack = null)
		{
			// prepare
			statusCode = statusCode < 1 ? (int)HttpStatusCode.InternalServerError : statusCode;
			var json = new JObject
			{
				{ "Message", message },
				{ "Type", type },
				{ "Verb", context.Request.Method },
				{ "Code", statusCode }
			};

			if (!string.IsNullOrWhiteSpace(correlationID))
				json["CorrelationID"] = correlationID;

			if (stack != null)
				json["StackTrace"] = stack;

			// update into context to use at status page middleware
			context.Items["StatusCode"] = statusCode;
			context.Items["ContentType"] = "application/json";
			context.Items["Body"] = json.ToString(Formatting.Indented);

			// set status code to raise status page middleware
			context.Response.StatusCode = statusCode;
		}

		/// <summary>
		/// Writes HTTP error as JSON
		/// </summary>
		/// <param name="context"></param>
		/// <param name="statusCode"></param>
		/// <param name="message"></param>
		/// <param name="type"></param>
		/// <param name="correlationID"></param>
		/// <param name="exception"></param>
		/// <param name="showStack"></param>
		public static void WriteHttpError(this HttpContext context, int statusCode, string message, string type, string correlationID, Exception exception, bool showStack = true)
		{
			JArray stack = null;
			if (exception != null && showStack)
			{
				stack = new JArray
				{
					new JObject
					{
						{ "Message", exception.Message },
						{ "Type", exception.GetType().ToString() },
						{ "Stack", exception.StackTrace }
					}
				};
				var inner = exception.InnerException;
				while (inner != null)
				{
					stack.Add(new JObject
					{
						{ "Message", inner.Message },
						{ "Type", inner.GetType().ToString() },
						{ "Stack", inner.StackTrace }
					});
					inner = inner.InnerException;
				}
			}
			context.WriteHttpError(statusCode, message, type, correlationID, stack);
		}
		#endregion

		#region Show page of HTTP status codes
		/// <summary>
		/// Shows the details page of a status code
		/// </summary>
		/// <param name="context"></param>
		/// <param name="getHtmlBody">The function to build the HTML body for displaying when no details of error is provided</param>
		/// <returns></returns>
		public static async Task ShowStatusPageAsync(this StatusCodeContext context, Func<int, HttpContext, string> getHtmlBody = null)
		{
			// prepare status
			var statusCode = context.HttpContext.Items.ContainsKey("StatusCode")
				? (int)context.HttpContext.Items["StatusCode"]
				: context.HttpContext.Response.StatusCode;

			// prepare content-type & body string
			var contentType = context.HttpContext.GetItem<string>("ContentType") ?? "text/plain";
			var bodystr = context.HttpContext.GetItem<string>("Body") ?? $"Error {statusCode}";
			if ("text/plain".Equals(contentType) && $"Error {statusCode}".Equals(bodystr))
			{
				contentType = "text/html";
				bodystr = getHtmlBody?.Invoke(statusCode, context.HttpContext) ?? context.HttpContext.GetHttpStatusCodeBody(statusCode);
			}

			// prepare body
			var body = bodystr.ToBytes();

			var encoding = context.HttpContext.Request.Headers["Accept-Encoding"].ToString() ?? "";
			if (body.Length < 1)
				encoding = null;
			else if (encoding.IsContains("gzip"))
				encoding = "gzip";
			else if (encoding.IsContains("deflate"))
				encoding = "deflate";
			else
				encoding = null;

			if (!string.IsNullOrWhiteSpace(encoding))
				body = body.Compress(encoding);

			// prepare headers
			var headers = context.HttpContext.GetItem<Dictionary<string, string>>("Headers") ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			headers["Server"] = context.HttpContext.GetServerName();
			headers["Cache-Control"] = context.HttpContext.GetItem<string>("CacheControl") ?? "private, no-store, no-cache";

			if (body.Length > 0)
			{
				headers["Content-Length"] = $"{body.Length}";
				headers["Content-Type"] = $"{contentType}{(contentType.IsEndsWith("; charset=utf-8") ? "" : "; charset=utf-8")}";
			}

			if (!string.IsNullOrWhiteSpace(encoding))
				headers["Content-Encoding"] = encoding;

			if (context.HttpContext.Items.ContainsKey("PipelineStopwatch") && context.HttpContext.Items["PipelineStopwatch"] is Stopwatch stopwatch)
			{
				stopwatch.Stop();
				headers["X-Execution-Times"] = stopwatch.GetElapsedTimes();
			}

			// response
			headers.ForEach(kvp => context.HttpContext.Response.Headers[kvp.Key] = kvp.Value);
			context.HttpContext.Response.StatusCode = statusCode;
			if (body.Length > 0)
				await context.HttpContext.WriteAsync(body).ConfigureAwait(false);
		}

		/// <summary>
		/// Adds a handler of StatusCodePages middleware for responses with specified status codes
		/// </summary>
		/// <param name="app"></param>
		/// <param name="getHtmlBody">The function to build the HTML body for displaying when no details of error is provided</param>
		public static IApplicationBuilder UseStatusCodeHandler(this IApplicationBuilder app, Func<int, HttpContext, string> getHtmlBody = null)
			=> app.UseStatusCodePages(context => context.ShowStatusPageAsync(getHtmlBody));
		#endregion

		#region Wrap a WebSocket connection of ASP.NET Core into WebSocket component
		/// <summary>
		/// Wraps a WebSocket connection of ASP.NET Core
		/// </summary>
		/// <param name="websocket"></param>
		/// <param name="context">The working context of ASP.NET Core</param>
		/// <param name="whenIsNotWebSocketRequestAsync">Action to run when the request is not WebSocket request</param>
		/// <returns></returns>
		public static async Task WrapAsync(this WebSocket websocket, HttpContext context, Func<HttpContext, Task> whenIsNotWebSocketRequestAsync = null)
		{
			if (context.WebSockets.IsWebSocketRequest)
				await websocket.WrapAsync(await context.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false), context.GetRequestUri(), context.GetRemoteEndPoint(), context.GetLocalEndPoint(), context.Request.Headers.ToDictionary()).ConfigureAwait(false);
			else if (whenIsNotWebSocketRequestAsync != null)
				await whenIsNotWebSocketRequestAsync(context).ConfigureAwait(false);
		}

		/// <summary>
		/// Wraps a WebSocket connection of ASP.NET Core
		/// </summary>
		/// <param name="websocket"></param>
		/// <param name="context">The working context of ASP.NET Core</param>
		/// <param name="whenIsNotWebSocketRequestAsync">Action to run when the request is not WebSocket request</param>
		/// <returns></returns>
		public static Task WrapWebSocketAsync(this WebSocket websocket, HttpContext context, Func<HttpContext, Task> whenIsNotWebSocketRequestAsync = null)
			=> websocket.WrapAsync(context, whenIsNotWebSocketRequestAsync);
		#endregion

	}
}