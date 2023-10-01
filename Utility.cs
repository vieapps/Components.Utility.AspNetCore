#region Related components
using System;
using System.Linq;
using System.IO;
using System.Text;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.WebSockets;
using net.vieapps.Components.Security;
#endregion

#if !SIGN
[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("VIEApps.Components.XUnitTests")]
#endif

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

		/// <summary>
		/// Gets the size for buffering when read/write a stream (default is 64K)
		/// </summary>
		public static int BufferSize { get; } = 1024 * 64;

		#region Extensions for working with environments
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

			if (exception is OperationCanceledException)
				return (int)HttpStatusCode.BadGateway;

			return exception.GetTypeName(true).IsEndsWith("NotFound")
					? (int)HttpStatusCode.NotFound
					: (int)HttpStatusCode.InternalServerError;
		}

		/// <summary>
		/// Gets the name of server
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
				+ $"<div>{(!string.IsNullOrWhiteSpace(correlationID) ? $"Correlation ID: {correlationID} - " : "")}"
				+ $"Powered by {context.GetServerName()} v{Assembly.GetExecutingAssembly().GetVersion(false)}</div>\r\n"
				+ "</body>\r\n</html>";
			return html;
		}

		static FileExtensionContentTypeProvider MimeTypeProvider { get; } = new FileExtensionContentTypeProvider();

		/// <summary>
		/// Gets the MIME type of a file
		/// </summary>
		/// <param name="filename"></param>
		/// <returns></returns>
		public static string GetMimeType(this string filename)
			=> AspNetCoreUtilityService.MimeTypeProvider.TryGetContentType(filename, out var mimeType) && !string.IsNullOrWhiteSpace(mimeType) ? mimeType : "application/octet-stream; charset=utf-8";

		/// <summary>
		/// Gets the MIME type of a file
		/// </summary>
		/// <param name="fileInfo"></param>
		/// <returns></returns>
		public static string GetMimeType(this FileInfo fileInfo)
			=> fileInfo?.Name?.GetMimeType() ?? "application/octet-stream; charset=utf-8";

		/// <summary>
		/// Parses the query of an uri
		/// </summary>
		/// <param name="uri"></param>
		/// /// <param name="onCompleted">Action to run on parsing completed</param>
		/// <returns>The collection of key and value pair</returns>
		public static Dictionary<string, string> ParseQuery(this Uri uri, Action<Dictionary<string, string>> onCompleted = null)
			=> QueryHelpers.ParseQuery(uri.Query).ToDictionary(onCompleted);

		/// <summary>
		/// Parses the query of the request in this context
		/// </summary>
		/// <param name="context"></param>
		/// /// <param name="onCompleted">Action to run on parsing completed</param>
		/// <returns>The collection of key and value pair</returns>
		public static Dictionary<string, string> ParseQuery(this HttpContext context, Action<Dictionary<string, string>> onCompleted = null)
			=> context.GetRequestUri().ParseQuery(onCompleted);

		/// <summary>
		/// Tries to get the value of a header parameter
		/// </summary>
		/// <param name="context"></param>
		/// <param name="name">The string that presents name of parameter want to get</param>
		/// <returns></returns>
		public static bool TryGetHeaderParameter(this HttpContext context, string name, out string value)
		{
			value = null;
			return !string.IsNullOrWhiteSpace(name) && context.Request.Headers.ToDictionary().TryGetValue(name, out value);
		}

		/// <summary>
		/// Gets the value of a header parameter
		/// </summary>
		/// <param name="context"></param>
		/// <param name="name">The string that presents name of parameter want to get</param>
		/// <returns></returns>
		public static string GetHeaderParameter(this HttpContext context, string name)
			=> context.TryGetHeaderParameter(name, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;

		/// <summary>
		/// Tries to get the value of a query parameter
		/// </summary>
		/// <param name="context"></param>
		/// <param name="name">The string that presents name of parameter want to get</param>
		/// <returns></returns>
		public static bool TryGetQueryParameter(this HttpContext context, string name, out string value)
		{
			value = null;
			return !string.IsNullOrWhiteSpace(name) && context.Request.QueryString.ToDictionary().TryGetValue(name, out value);
		}

		/// <summary>
		/// Gets the value of a query parameter
		/// </summary>
		/// <param name="context"></param>
		/// <param name="name">The string that presents name of parameter want to get</param>
		/// <returns></returns>
		public static string GetQueryParameter(this HttpContext context, string name)
			=> context.TryGetQueryParameter(name, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;

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
			=> context.TryGetHeaderParameter("Referer", out var value) && !string.IsNullOrWhiteSpace(value)
				? new Uri(value)
				: null;

		/// <summary>
		/// Gets the origin Uniform Resource Identifier (URI) of the request that was sent by the client
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static Uri GetOriginUri(this HttpContext context)
			=> context.TryGetHeaderParameter("Origin", out var value) && !string.IsNullOrWhiteSpace(value)
				? new Uri(value)
				: null;

		/// <summary>
		/// Gets the user-agent string of the request that was sent by the client
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static string GetUserAgent(this HttpContext context)
			=> context.GetHeaderParameter("User-Agent") ?? "";

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
					var uri = context.TryGetHeaderParameter("x-original-remote-endpoint", out var value)
						? new Uri(value)
						: context.TryGetHeaderParameter("cf-connecting-ip", out value)
							? new Uri($"https://{value}:{new Uri($"https://{context.GetHeaderParameter("x-original-for")}").Port}")
							: new Uri($"https://{context.GetHeaderParameter("x-original-for")}");
					endpoint = new IPEndPoint(IPAddress.Parse(uri.Host), uri.Port);
				}
				catch { }
			return endpoint;
		}

		/// <summary>
		/// Appends cookies into response
		/// </summary>
		/// <param name="context"></param>
		/// <param name="cookies"></param>
		public static void AppendCookies(this HttpContext context, IEnumerable<Cookie> cookies)
		{
			cookies?.ForEach(cookie => context.Response.Cookies.Append
			(
				cookie.Name,
				cookie.Value,
				new CookieOptions
				{
					Domain = cookie.Domain,
					Path = cookie.Path,
					Expires = cookie.Expires,
					Secure = cookie.Secure,
					HttpOnly = cookie.HttpOnly
				}
			));
		}

		/// <summary>
		/// Gets the request content-encoding
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static string GetContentEncoding(this HttpContext context)
		{
			var encoding = context.Request.Headers["Accept-Encoding"].ToString();
			return encoding.IsContains("br") || encoding.IsContains("*")
				? "br"
				: encoding.IsContains("gzip")
					? "gzip"
					: encoding.IsContains("deflate")
						? "deflate"
						: null;
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
		/// Generates ETag from this uri
		/// </summary>
		/// <param name="uri"></param>
		/// <param name="prefix"></param>
		/// <param name="queryIncluded"></param>
		/// <returns></returns>
		public static string GenerateETag(this Uri uri, string prefix = null, bool queryIncluded = false)
			=> $"{prefix ?? "v"}#{(queryIncluded ? $"{uri}".ToLower() : uri.GetUrl(true, false)).GenerateUUID()}";

		/// <summary>
		/// Generates ETag from the uri of this context
		/// </summary>
		/// <param name="context"></param>
		/// <param name="prefix"></param>
		/// <param name="queryIncluded"></param>
		/// <returns></returns>
		public static string GenerateETag(this HttpContext context, string prefix = null, bool queryIncluded = false)
			=> context.GetRequestUri().GenerateETag(prefix, queryIncluded);
		#endregion

		#region Read data from request
		/// <summary>
		/// Reads data from request body asynchronously
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static async Task<byte[]> ReadAsync(this HttpContext context, CancellationToken cancellationToken = default)
		{
			var buffer = new byte[AspNetCoreUtilityService.BufferSize];
			var data = Array.Empty<byte>();
			int read;
			do
			{
				read = await context.Request.Body.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
				if (read > 0)
					data = data.Concat(buffer.Take(0, read));
			}
			while (read > 0);
			return data;
		}

		/// <summary>
		/// Reads data as text from request body asynchronously
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static Task<string> ReadTextAsync(this HttpContext context, CancellationToken cancellationToken = default)
			=> context.Request.Body.ReadAllAsync(cancellationToken);
		#endregion

		#region Response helpers: set headers, flush, redirect, ...
		/// <summary>
		/// Sets the approriate headers of response
		/// </summary>
		/// <param name="context"></param>
		/// <param name="statusCode">The HTTP status code</param>
		/// <param name="headers">The HTTP headers</param>
		public static void SetResponseHeaders(this HttpContext context, int statusCode, Dictionary<string, string> headers = null)
		{
			// prepare
			headers = new Dictionary<string, string>(headers ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
			{
				["Server"] = context.GetServerName()
			};
			if (context.Items.ContainsKey("PipelineStopwatch") && context.Items["PipelineStopwatch"] is Stopwatch stopwatch)
			{
				stopwatch.Stop();
				headers["X-Execution-Times"] = stopwatch.GetElapsedTimes();
			}

			// update into context to use at status page middleware
			context.SetItem("StatusCode", statusCode);
			context.SetItem("Body", "");
			context.SetItem("Headers", headers);
			if (headers.TryGetValue("Cache-Control", out var cacheControl))
				context.SetItem("CacheControl", cacheControl);

			// update headers
			headers.ForEach(kvp => context.Response.Headers[kvp.Key] = kvp.Value);
			context.Response.StatusCode = statusCode;
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
				if (expires != default && expires.Ticks > 0)
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

			if (lastModified > 0)
				headers["Last-Modified"] = lastModified.FromUnixTimestamp().ToHttpString();

			if (!string.IsNullOrWhiteSpace(cacheControl))
				headers["Cache-Control"] = cacheControl;

			if (!string.IsNullOrWhiteSpace(correlationID))
				headers["X-Correlation-ID"] = correlationID;

			// update
			context.SetResponseHeaders(statusCode, headers);
		}

		/// <summary>
		/// Asynchronously sends all currently buffered output to the client
		/// </summary>
		/// <param name="context"></param>
		/// <param name="cancellationToken"></param>
		public static Task FlushAsync(this HttpContext context, CancellationToken cancellationToken = default)
			=> context.Response.Body.FlushAsync(cancellationToken);

		/// <summary>
		/// Redirects the response by send the redirect status code (301 or 302) to client
		/// </summary>
		/// <param name="context"></param>
		/// <param name="location">The location to redirect to - must be encoded</param>
		/// <param name="redirectPermanently">true to use 301 (Moved Permanently) instead of 302 (Redirect Temporary)</param>
		public static void Redirect(this HttpContext context, string location, bool redirectPermanently = false)
		{
			if (!string.IsNullOrWhiteSpace(location))
				context.SetResponseHeaders(redirectPermanently ? (int)HttpStatusCode.MovedPermanently : (int)HttpStatusCode.Redirect, new Dictionary<string, string> { ["Location"] = location });
		}

		/// <summary>
		/// Redirects the response by send the redirect status code (301 or 302) to client
		/// </summary>
		/// <param name="context"></param>
		/// <param name="uri">The location to redirect to</param>
		/// <param name="redirectPermanently">true to use 301 (Moved Permanently) instead of 302 (Redirect Temporary)</param>
		public static void Redirect(this HttpContext context, Uri uri, bool redirectPermanently = false)
		{
			if (uri == null)
				return;
			var location = $"{uri.Scheme}://{uri.Host}{(uri.Port != 80 && uri.Port != 443 ? $":{uri.Port}" : "")}/";
			var pathSegments = uri.GetRequestPathSegments();
			if (pathSegments != null && pathSegments.Length > 0)
				location += pathSegments.ToString("/", segment => segment.UrlDecode().UrlEncode());
			var query = uri.ParseQuery();
			if (query != null && query.Count > 0)
				location += "?" + query.ToString("&", kvp => $"{kvp.Key.UrlEncode()}={kvp.Value.UrlDecode().UrlEncode()}");
			if (!string.IsNullOrWhiteSpace(uri.Fragment))
				location += uri.Fragment;
			context.Redirect(location, redirectPermanently);
		}
		#endregion

		#region Write a stream to the response body
		/// <summary>
		/// Writes the stream to the output response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="stream">The stream to write</param>
		/// <param name="headers">The headers</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static async Task WriteAsync(this HttpContext context, Stream stream, Dictionary<string, string> headers, IEnumerable<Cookie> cookies, CancellationToken cancellationToken)
		{
			// check ETag for supporting resumeable downloaders
			var eTag = headers?.FirstOrDefault(kvp => kvp.Key.IsEquals("ETag")).Value;
			if (!string.IsNullOrWhiteSpace(eTag))
			{
				var requestETag = context.GetRequestETag();
				if (!string.IsNullOrWhiteSpace(requestETag) && !eTag.Equals(requestETag))
				{
					context.SetResponseHeaders((int)HttpStatusCode.PreconditionFailed, null, 0, "private", null);
					await context.FlushAsync(cancellationToken).ConfigureAwait(false);
					return;
				}
			}

			// prepare position for flushing as partial blocks
			var flushAsPartialContent = false;
			var totalBytes = stream.Length;
			long startBytes = 0, endBytes = totalBytes - 1;
			var requestedRange = context.Request.Headers["Range"].First();

			if (!string.IsNullOrWhiteSpace(requestedRange))
			{
				flushAsPartialContent = true;
				var range = requestedRange.ToList("=").Last().ToList("-");

				startBytes = range[0].As<long>();
				if (startBytes >= totalBytes)
				{
					context.SetResponseHeaders((int)HttpStatusCode.PreconditionFailed, null, 0, "private", null);
					return;
				}

				if (startBytes < 0)
					startBytes = 0;

				if (range.Count > 1)
					try
					{
						endBytes = range[1].As<long>();
					}
					catch { }

				if (endBytes > totalBytes - 1)
					endBytes = totalBytes - 1;
			}

			headers = new Dictionary<string, string>(headers ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase);
			if (!string.IsNullOrWhiteSpace(eTag))
				headers["Accept-Ranges"] = "bytes";

			if (flushAsPartialContent)
			{
				headers["Content-Length"] = $"{endBytes - startBytes + 1}";
				if (startBytes > -1)
					headers["Content-Range"] = $"bytes {startBytes}-{endBytes}/{totalBytes}";
			}

			// update headers & cookies
			context.SetResponseHeaders(flushAsPartialContent ? (int)HttpStatusCode.PartialContent : (int)HttpStatusCode.OK, headers);
			context.AppendCookies(cookies);

			// read and flush stream data to response stream
			if (flushAsPartialContent && startBytes > 0)
				stream.Seek(startBytes, SeekOrigin.Begin);

			var size = AspNetCoreUtilityService.BufferSize;
			if (size > (endBytes - startBytes))
				size = (int)(endBytes - startBytes) + 1;

			var buffer = new byte[size];
			var total = (int)Math.Ceiling((endBytes - startBytes + 0.0) / size);
			var count = 0;
			while (count < total)
			{
				var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
#if NETSTANDARD2_0
				await context.Response.Body.WriteAsync(buffer, 0, read).WithCancellationToken(cancellationToken).ConfigureAwait(false);
#else
				await context.Response.Body.WriteAsync(buffer.Take(0, read), cancellationToken).ConfigureAwait(false);
#endif
				await context.Response.Body.FlushAsync(cancellationToken).ConfigureAwait(false);
				count++;
			}
		}

		/// <summary>
		/// Writes the stream to the output response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="stream">The stream to write</param>
		/// <param name="headers">The headers</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, Stream stream, Dictionary<string, string> headers, CancellationToken cancellationToken = default)
			=> context.WriteAsync(stream, headers, null, cancellationToken);

		/// <summary>
		/// Writes the stream to the output response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="stream">The stream to write</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, Stream stream, CancellationToken cancellationToken = default)
			=> context.WriteAsync(stream, null, null, cancellationToken);

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
		public static Task WriteAsync(this HttpContext context, Stream stream, string contentType, string contentDisposition = null, string eTag = null, long lastModified = 0, string cacheControl = null, TimeSpan expires = default, Dictionary<string, string> headers = null, string correlationID = null, CancellationToken cancellationToken = default)
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
				if (expires != default && expires.Ticks > 0)
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
		public static Task WriteAsync(this HttpContext context, Stream stream, string contentType, string contentDisposition, string eTag, long lastModified, string cacheControl, TimeSpan expires, CancellationToken cancellationToken = default)
			=> context.WriteAsync(stream, contentType, contentDisposition, eTag, lastModified, cacheControl, expires, null, null, cancellationToken);
		#endregion

		#region Write a file to the response body
		/// <summary>
		/// Writes the content of a file (binary) to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="fileInfo">The information of the file to write to output stream</param>
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
		public static async Task WriteAsync(this HttpContext context, FileInfo fileInfo, string contentType = null, string contentDisposition = null, string eTag = null, long lastModified = 0, string cacheControl = null, TimeSpan expires = default, Dictionary<string, string> headers = null, string correlationID = null, CancellationToken cancellationToken = default)
		{
			if (fileInfo == null || !fileInfo.Exists)
				throw new FileNotFoundException($"Not found{(fileInfo != null ? $" [{fileInfo.Name}]" : "")}");

			using (var stream = new FileStream(fileInfo.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, AspNetCoreUtilityService.BufferSize, true))
				await context.WriteAsync(
					stream,
					contentType ?? fileInfo.GetMimeType(),
					contentDisposition,
					eTag,
					string.IsNullOrWhiteSpace(eTag) ? 0 : lastModified > 0 ? lastModified : fileInfo.LastWriteTime.ToUnixTimestamp(),
					string.IsNullOrWhiteSpace(eTag) ? null : cacheControl ?? "public",
					string.IsNullOrWhiteSpace(eTag) ? TimeSpan.Zero : expires != TimeSpan.Zero && expires.Ticks > 0 ? expires : TimeSpan.FromDays(366),
					headers,
					correlationID,
					cancellationToken
				).ConfigureAwait(false);
		}

		/// <summary>
		/// Writes the content of a file (binary) to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="fileInfo">The information of the file to write to output stream</param>
		/// <param name="contentType">The MIME type</param>
		/// <param name="contentDisposition">The string that presents name of attachment file, let it empty/null for writting showing/displaying (not for downloading attachment file)</param>
		/// <param name="eTag">The entity tag</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, FileInfo fileInfo, string contentType, string contentDisposition = null, string eTag = null, string correlationID = null, CancellationToken cancellationToken = default)
			=> context.WriteAsync(fileInfo, contentType, contentDisposition, eTag, 0, null, TimeSpan.Zero, null, correlationID, cancellationToken);

		/// <summary>
		/// Writes the content of a file (binary) to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="fileInfo">The information of the file</param>
		/// <param name="contentDisposition">The string that presents name of attachment file, let it empty/null for writting showing/displaying (not for downloading attachment file)</param>
		/// <param name="eTag">The entity tag</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, FileInfo fileInfo, string contentDisposition, string eTag = null, CancellationToken cancellationToken = default)
			=> context.WriteAsync(fileInfo, null, contentDisposition, eTag, null, cancellationToken);

		/// <summary>
		/// Writes the content of a file (binary) to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="fileInfo">The information of the file</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, FileInfo fileInfo, CancellationToken cancellationToken = default)
			=> context.WriteAsync(fileInfo, null, null, cancellationToken);
		#endregion

		#region Write binary data to the response body
		/// <summary>
		/// Writes binary data to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="buffer"></param>
		/// <param name="offset"></param>
		/// <param name="count"></param>
		/// <param name="headers"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, byte[] buffer, int offset, int count, Dictionary<string, string> headers, CancellationToken cancellationToken = default)
		{
			if (headers != null && headers.Any())
				context.SetResponseHeaders((int)HttpStatusCode.OK, headers);
#if NETSTANDARD2_0
			return context.Response.Body.WriteAsync(buffer, offset > -1 ? offset : 0, count > 0 ? count : buffer.Length).WithCancellationToken(cancellationToken);
#else
			return context.Response.Body.WriteAsync(buffer.AsMemory(offset > -1 ? offset : 0, count > 0 ? count : buffer.Length), cancellationToken).AsTask();
#endif
		}

		/// <summary>
		/// Writes binary data to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="buffer"></param>
		/// <param name="headers"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, byte[] buffer, Dictionary<string, string> headers, CancellationToken cancellationToken = default)
			=> context.WriteAsync(buffer, 0, 0, headers, cancellationToken);

		/// <summary>
		/// Writes binary data to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="buffer"></param>
		/// <param name="offset"></param>
		/// <param name="count"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, byte[] buffer, int offset = 0, int count = 0, CancellationToken cancellationToken = default)
			=> context.WriteAsync(buffer, offset, count, null, cancellationToken);

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
		public static Task WriteAsync(this HttpContext context, ArraySegment<byte> buffer, CancellationToken cancellationToken = default)
			=> context.WriteAsync(buffer.ToBytes(), cancellationToken);

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
		public static async Task WriteAsync(this HttpContext context, byte[] buffer, string contentType, string contentDisposition = null, string eTag = null, long lastModified = 0, string cacheControl = null, TimeSpan expires = default, Dictionary<string, string> headers = null, string correlationID = null, CancellationToken cancellationToken = default)
		{
			using (var stream = buffer.ToMemoryStream())
				await context.WriteAsync(stream, contentType, contentDisposition, eTag, lastModified, cacheControl, expires, headers, correlationID, cancellationToken).ConfigureAwait(false);
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
		public static Task WriteAsync(this HttpContext context, byte[] buffer, string contentType, string contentDisposition, string eTag, long lastModified, string cacheControl, TimeSpan expires, CancellationToken cancellationToken = default)
			=> context.WriteAsync(buffer, contentType, contentDisposition, eTag, lastModified, cacheControl, expires, null, null, cancellationToken);
		#endregion

		#region Write text data to the response body
		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="encoding"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, string text, Encoding encoding = null, CancellationToken cancellationToken = default)
			=> context.WriteAsync(text.ToBytes(encoding), cancellationToken);

		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, string text, CancellationToken cancellationToken)
			=> context.WriteAsync(text.ToBytes(), cancellationToken);

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
		public static Task WriteAsync(this HttpContext context, string text, string contentType, string eTag, long lastModified, string cacheControl, TimeSpan expires, string correlationID = null, CancellationToken cancellationToken = default)
		{
			context.SetResponseHeaders((int)HttpStatusCode.OK, contentType, eTag, lastModified, cacheControl, expires, correlationID);
			return context.WriteAsync(text.ToBytes(), cancellationToken);
		}

		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="contentType"></param>
		/// <param name="correlationID"></param>
		public static Task WriteAsync(this HttpContext context, string text, string contentType = "text/html", string correlationID = null, CancellationToken cancellationToken = default)
			=> context.WriteAsync(text, contentType, null, 0, null, default, correlationID, cancellationToken);
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
		public static Task WriteAsync(this HttpContext context, JToken json, Formatting formatting, string eTag, long lastModified, string cacheControl, TimeSpan expires, string correlationID = null, CancellationToken cancellationToken = default)
			=> context.WriteAsync(json?.ToString(formatting) ?? "{}", "application/json", eTag, lastModified, cacheControl, expires, correlationID, cancellationToken);

		/// <summary>
		/// Writes the JSON to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="json"></param>
		/// <param name="formatting"></param>
		/// <param name="correlationID"></param>
		public static Task WriteAsync(this HttpContext context, JToken json, Formatting formatting = Formatting.None, string correlationID = null, CancellationToken cancellationToken = default)
			=> context.WriteAsync(json, formatting, null, 0, null, default, correlationID, cancellationToken);

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
		/// <param name="body"></param>
		/// <param name="headers"></param>
		public static void ShowError(this HttpContext context, int statusCode, string body, Dictionary<string, string> headers = null)
		{
			context.SetItem("StatusCode", statusCode);
			context.SetItem("ContentType", "text/html; charset=utf-8");
			context.SetItem("Body", body);
			if (headers != null && headers.Any())
				context.SetItem("Headers", headers);
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
		/// <param name="stack"></param>
		/// <param name="showStack"></param>
		public static void ShowError(this HttpContext context, int statusCode, string message, string type, string correlationID = null, string stack = null, bool showStack = true)
		{
			statusCode = statusCode < 1 ? (int)HttpStatusCode.InternalServerError : statusCode;
			context.ShowError(statusCode, context.GetHttpStatusCodeBody(statusCode, message, type, correlationID, stack, showStack));
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
		public static void ShowError(this HttpContext context, int statusCode, string message, string type, string correlationID, Exception ex, bool showStack = true)
		{
			var stack = string.Empty;
			if (ex != null && showStack)
			{
				stack = ex.StackTrace;
				var counter = 1;
				var inner = ex.InnerException;
				while (inner != null)
				{
					stack += "\r\n" + $" ----- Inner [{counter}] --------------- " + "\r\n" + inner.StackTrace;
					inner = inner.InnerException;
					counter++;
				}
			}
			context.ShowError(statusCode, message, type, correlationID, stack, showStack);
		}
		#endregion

		#region Write HTTP error as JSON
		/// <summary>
		/// Writes HTTP error as JSON
		/// </summary>
		/// <param name="context"></param>
		/// <param name="statusCode"></param>
		/// <param name="body"></param>
		/// <param name="headers"></param>
		public static void WriteError(this HttpContext context, int statusCode, JToken body, Dictionary<string, string> headers = null)
		{
			context.SetItem("StatusCode", statusCode);
			context.SetItem("ContentType", "application/json; charset=utf-8");
			context.SetItem("Body", body.ToString(Formatting.Indented));
			if (headers != null && headers.Any())
				context.SetItem("Headers", headers);
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
		/// <param name="stacks"></param>
		public static void WriteError(this HttpContext context, int statusCode, string message, string type, string correlationID = null, JArray stacks = null)
		{
			// prepare
			statusCode = statusCode < 1 ? (int)HttpStatusCode.InternalServerError : statusCode;
			var body = new JObject
			{
				{ "Message", message },
				{ "Type", type },
				{ "Verb", context.Request.Method },
				{ "Code", statusCode }
			};

			if (stacks != null)
				body["StackTrace"] = stacks;

			if (!string.IsNullOrWhiteSpace(correlationID))
				body["CorrelationID"] = correlationID;

			// write error
			context.WriteError(statusCode, body);
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
		public static void WriteError(this HttpContext context, int statusCode, string message, string type, string correlationID, Exception exception, bool showStack = true)
			=> context.WriteError(statusCode, message, type, correlationID, showStack ? exception?.GetStacks() : null);

		/// <summary>
		/// Gets the collection of stack trace
		/// </summary>
		/// <param name="exception"></param>
		/// <returns></returns>
		public static JArray GetStacks(this Exception exception)
		{
			var stacks = new JArray { $"{exception.Message} [{exception.GetType()}] {exception.StackTrace}" };
			var inner = exception.InnerException;
			while (inner != null)
			{
				stacks.Add($"{inner.Message} [{inner.GetType()}] {inner.StackTrace}");
				inner = inner.InnerException;
			}
			return stacks;
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
				? context.HttpContext.GetItem<int>("StatusCode")
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

			var encoding = body.Length < 1 ? null : context.HttpContext.GetContentEncoding();
			if (!string.IsNullOrWhiteSpace(encoding))
				body = body.Compress(encoding);

			// prepare headers
			var headers = context.HttpContext.GetItem<Dictionary<string, string>>("Headers") ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			headers["Access-Control-Allow-Origin"] = "*";
			headers["Server"] = context.HttpContext.GetServerName();
			if (!headers.ContainsKey("Cache-Control"))
				headers["Cache-Control"] = context.HttpContext.GetItem<string>("CacheControl") ?? "private, no-store, no-cache";

			if (body.Length > 0)
			{
				headers["Content-Length"] = $"{body.Length}";
				headers["Content-Type"] = $"{contentType}{(contentType.IsEndsWith("; charset=utf-8") ? "" : "; charset=utf-8")}";
				if (!string.IsNullOrWhiteSpace(encoding))
					headers["Content-Encoding"] = encoding;
			}

			if (context.HttpContext.Items.TryGetValue("PipelineStopwatch", out object value) && value is Stopwatch stopwatch)
			{
				stopwatch.Stop();
				headers["X-Execution-Times"] = stopwatch.GetElapsedTimes();
			}

			// response
			headers.ForEach(kvp =>
			{
				try
				{
					context.HttpContext.Response.Headers[kvp.Key] = kvp.Value;
				}
				catch { }
			});
			context.HttpContext.Response.StatusCode = statusCode;
			if (body.Length > 0)
				await context.HttpContext.WriteAsync(body).ConfigureAwait(false);
			await context.HttpContext.FlushAsync().ConfigureAwait(false);
		}

		/// <summary>
		/// Adds a handler of StatusCodePages middleware for responses with specified status codes
		/// </summary>
		/// <param name="appBuilder"></param>
		/// <param name="getHtmlBody">The function to build the HTML body for displaying when no details of error is provided</param>
		public static IApplicationBuilder UseStatusCodeHandler(this IApplicationBuilder appBuilder, Func<int, HttpContext, string> getHtmlBody = null)
			=> appBuilder.UseStatusCodePages(context => context.ShowStatusPageAsync(getHtmlBody));
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

		#region Persists the data-protection keys to distributed cache
		/// <summary>
		/// Persists the data-protection keys to distributed cache
		/// </summary>
		/// <param name="dataProtection"></param>
		/// <param name="options">The options</param>
		/// <returns></returns>
		public static IDataProtectionBuilder PersistKeysToDistributedCache(this IDataProtectionBuilder dataProtection, DistributedXmlRepositoryOptions options = null)
		{
			dataProtection.Services.Configure<KeyManagementOptions>(keyOptions => keyOptions.XmlRepository = new DistributedXmlRepository(dataProtection.Services.BuildServiceProvider().GetService<IDistributedCache>(), options ?? new DistributedXmlRepositoryOptions()));
			return dataProtection;
		}
		#endregion

	}
}