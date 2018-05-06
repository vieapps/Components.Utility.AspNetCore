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

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json.Linq;

using net.vieapps.Components.WebSockets;
using net.vieapps.Components.Security;
using net.vieapps.Components.Caching;
#endregion

namespace net.vieapps.Components.Utility
{
	/// <summary>
	/// Static servicing methods for working with ASP.NET Core
	/// </summary>
	public static partial class AspNetCoreUtilityService
	{

		#region Extension helpers
		internal const long MinSmallFileSize = 1024 * 40;
		internal const long MaxSmallFileSize = 1024 * 1024 * 2;

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
		/// Sets the approriate headers of response
		/// </summary>
		/// <param name="context"></param>
		/// <param name="statusCode"></param>
		/// <param name="contentType"></param>
		/// <param name="eTag"></param>
		/// <param name="lastModified"></param>
		/// <param name="correlationID"></param>
		/// <param name="additionalHeaders"></param>
		public static void SetResponseHeaders(this HttpContext context, int statusCode, string contentType, string eTag = null, string lastModified = null, string correlationID = null, Dictionary<string, string> additionalHeaders = null)
		{
			// status code
			context.Response.StatusCode = statusCode;

			// prepare headers
			var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
			{
				{ "Server", "VIEApps NGX" },
				{ "Content-Type", $"{contentType}; charset=utf-8" }
			};

			if (!string.IsNullOrWhiteSpace(eTag))
				headers.Add("ETag", $"\"{eTag}\"");

			if (!string.IsNullOrWhiteSpace(lastModified))
				headers.Add("Last-Modified", lastModified);

			if (!string.IsNullOrWhiteSpace(correlationID))
				headers.Add("X-Correlation-ID", correlationID);

			additionalHeaders?.Where(kvp => !headers.ContainsKey(kvp.Key)).ForEach(kvp => headers[kvp.Key] = kvp.Value);

			if (context.Items.ContainsKey("PipelineStopwatch") && context.Items["PipelineStopwatch"] is Stopwatch stopwatch)
			{
				stopwatch.Stop();
				headers.Add("X-Execution-Times", stopwatch.GetElapsedTimes());
			}

			// update headers
			headers.Where(kvp => !context.Response.Headers.ContainsKey(kvp.Key)).ForEach(kvp => context.Response.Headers.Add(kvp.Key, kvp.Value));
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
		/// Gets the original Uniform Resource Identifier (URI) of the request that was sent by the client
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static Uri GetRequestUri(this HttpContext context)
		{
			return new Uri($"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}{context.Request.PathBase}{context.Request.QueryString}");
		}

		/// <summary>
		/// Parses the query of an uri
		/// </summary>
		/// <param name="uri"></param>
		/// /// <param name="onCompleted">Action to run on parsing completed</param>
		/// <returns>The collection of key and value pair</returns>
		public static Dictionary<string, string> ParseQuery(this Uri uri, Action<Dictionary<string, string>> onCompleted = null)
		{
			var query = QueryHelpers.ParseQuery(uri.Query).ToDictionary(kvp => kvp.Key, kvp => kvp.Value.First(), StringComparer.OrdinalIgnoreCase);
			onCompleted?.Invoke(query);
			return query;
		}
		#endregion

		#region Flush, Clear & End response
		/// <summary>
		/// Sends all currently buffered output to the client
		/// </summary>
		/// <param name="context"></param>
		public static void Flush(this HttpContext context)
		{
			context.Response.Body.Flush();
		}

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
		/// Clears the response stream
		/// </summary>
		/// <param name="context"></param>
		public static void Clear(this HttpContext context)
		{
			try
			{
				context.Response.Headers.Clear();
				context.Response.Body = new MemoryStream();
			}
			catch { }
		}

		/// <summary>
		/// Closes the response stream (means end the response)
		/// </summary>
		/// <param name="response"></param>
		public static void End(this HttpResponse response)
		{
			try
			{
				response.Body.Flush();
				response.Body.Dispose();
			}
			catch { }
		}
		#endregion

		#region Read data from request
		/// <summary>
		/// Reads data from request body
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static byte[] Read(this HttpContext context)
		{
			var buffer = new byte[context.GetBodyRequestMaxLength()];
			var read = context.Request.Body.Read(buffer, 0, buffer.Length);
			return buffer.Take(0, read);
		}

		/// <summary>
		/// Reads data from request body
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static async Task<byte[]> ReadAsync(this HttpContext context, CancellationToken cancellationToken = default(CancellationToken))
		{
			var buffer = new byte[context.GetBodyRequestMaxLength()];
			var read = await context.Request.Body.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
			return buffer.Take(0, read);
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
		{
			context.Response.Body.Write(buffer, offset > -1 ? offset : 0, count > 0 ? count : buffer.Length);
		}

		/// <summary>
		/// Writes binary data to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="buffer"></param>
		/// <returns></returns>
		public static void Write(this HttpContext context, ArraySegment<byte> buffer)
		{
			context.Response.Body.Write(buffer.Array, buffer.Offset, buffer.Count);
		}

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
		public static Task WriteAsync(this HttpContext context, ArraySegment<byte> buffer, CancellationToken cancellationToken = default(CancellationToken))
		{
			return context.WriteAsync(buffer.Array, buffer.Offset, buffer.Count, cancellationToken);
		}

		/// <summary>
		/// Writes the stream to the output response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="stream">The stream to write</param>
		/// <param name="contentType">The MIME type</param>
		/// <param name="eTag">The entity tag</param>
		/// <param name="lastModified">The last-modified time in HTTP date-time format</param>
		/// <param name="contentDisposition">The string that presents name of attachment file, let it empty/null for writting showing/displaying (not for downloading attachment file)</param>
		/// <param name="blockSize">Size of one block to write</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static async Task WriteAsync(this HttpContext context, Stream stream, string contentType, string eTag = null, string lastModified = null, string contentDisposition = null, int blockSize = 0, CancellationToken cancellationToken = default(CancellationToken))
		{
			// validate whether the file is too large
			var totalBytes = stream.Length;
			if (totalBytes > context.GetBodyRequestMaxLength())
			{
				context.Response.StatusCode = (int)HttpStatusCode.RequestEntityTooLarge;
				return;
			}

			// check ETag for supporting resumeable downloaders
			if (!string.IsNullOrWhiteSpace(eTag))
			{
				var requestETag = context.GetRequestETag();
				if (!string.IsNullOrWhiteSpace(requestETag) && !eTag.Equals(requestETag))
				{
					context.Response.StatusCode = (int)HttpStatusCode.PreconditionFailed;
					return;
				}
			}

			// prepare position for flushing as partial blocks
			var flushAsPartialContent = false;
			long startBytes = 0, endBytes = totalBytes - 1;
			if (!string.IsNullOrWhiteSpace(context.Request.Headers["Range"].First()))
			{
				var requestedRange = context.Request.Headers["Range"].First();
				var range = requestedRange.Split(new char[] { '=', '-' });

				startBytes = range[1].CastAs<long>();
				if (startBytes >= totalBytes)
				{
					context.Response.StatusCode = (int)HttpStatusCode.PreconditionFailed;
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

			// prepare headers
			var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
			{
				{ "Content-Length", $"{(endBytes - startBytes) + 1}" },
			};

			if (flushAsPartialContent && startBytes > -1)
				headers.Add("Content-Range", $"bytes {startBytes}-{endBytes}/{totalBytes}");

			if (!string.IsNullOrWhiteSpace(eTag))
				headers.Add("Accept-Ranges", "bytes");

			if (!string.IsNullOrWhiteSpace(contentDisposition))
				headers.Add("Content-Disposition", $"Attachment; Filename=\"{contentDisposition}\"");

			// update headers
			try
			{
				context.SetResponseHeaders(flushAsPartialContent ? (int)HttpStatusCode.PartialContent : (int)HttpStatusCode.OK, contentType, eTag, lastModified, null, headers);
				await context.FlushAsync(cancellationToken).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
				return;
			}
			catch (Exception)
			{
				throw;
			}

			// write small file directly to output stream
			if (!flushAsPartialContent && totalBytes <= AspNetCoreUtilityService.MaxSmallFileSize)
				try
				{
					var buffer = new byte[totalBytes];
					var readBytes = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
					await context.WriteAsync(buffer, 0, readBytes, cancellationToken).ConfigureAwait(false);
					await context.FlushAsync(cancellationToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException)
				{
					return;
				}
				catch (Exception)
				{
					throw;
				}

			// flush to output stream
			else
			{
				// prepare blocks for writing
				var packSize = blockSize > 0
					? blockSize
					: (int)AspNetCoreUtilityService.MinSmallFileSize;
				if (packSize > (endBytes - startBytes))
					packSize = (int)(endBytes - startBytes) + 1;
				var totalBlocks = (int)Math.Ceiling((endBytes - startBytes + 0.0) / packSize);

				// jump to requested position
				stream.Seek(startBytes > 0 ? startBytes : 0, SeekOrigin.Begin);

				// read and flush stream data to response stream
				var buffer = new byte[packSize];
				var readBlocks = 0;
				while (readBlocks < totalBlocks)
					try
					{
						var readBytes = await stream.ReadAsync(buffer, 0, packSize, cancellationToken).ConfigureAwait(false);
						if (readBytes > 0)
						{
							await context.WriteAsync(buffer, 0, readBytes, cancellationToken).ConfigureAwait(false);
							await context.FlushAsync(cancellationToken).ConfigureAwait(false);
						}
						readBlocks++;
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
		/// Writes binary data to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="buffer">The data to write</param>
		/// <param name="contentType">The MIME type</param>
		/// <param name="eTag">The entity tag</param>
		/// <param name="lastModified">The last-modified time in HTTP date-time format</param>
		/// <param name="contentDisposition">The string that presents name of attachment file, let it empty/null for writting showing/displaying (not for downloading attachment file)</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static async Task WriteAsync(this HttpContext context, byte[] buffer, string contentType, string eTag = null, string lastModified = null, string contentDisposition = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			using (var stream = buffer.ToMemoryStream())
			{
				await context.WriteAsync(stream, contentType, eTag, lastModified, contentDisposition, 0, cancellationToken).ConfigureAwait(false);
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
		public static async Task WriteAsync(this HttpContext context, FileInfo fileInfo, string contentType, string eTag = null, string contentDisposition = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			if (fileInfo == null || !fileInfo.Exists)
				throw new FileNotFoundException("Not found" + (fileInfo != null ? " [" + fileInfo.Name + "]" : ""));

			using (var stream = new FileStream(fileInfo.FullName, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true))
			{
				await context.WriteAsync(stream, contentType, eTag, fileInfo.LastWriteTime.ToHttpString(), contentDisposition, 0, cancellationToken).ConfigureAwait(false);
			}
		}
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
				filename = filename ?? dataSet.Tables[0].TableName + ".xlsx";
				await context.WriteAsync(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", null, null, filename, TextFileReader.BufferSize, cancellationToken).ConfigureAwait(false);
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
		{
			return context.WriteAsExcelDocumentAsync(dataSet, null, cancellationToken);
		}
		#endregion

		#region Write text data to the response body
		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="encoding"></param>
		public static void Write(this HttpContext context, string text, Encoding encoding = null)
		{
			context.Write(text.ToBytes(encoding));
		}

		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="encoding"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, string text, Encoding encoding = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			return context.WriteAsync(text.ToBytes(encoding).ToArraySegment(), cancellationToken);
		}

		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, string text, CancellationToken cancellationToken)
		{
			return context.WriteAsync(text.ToBytes().ToArraySegment(), cancellationToken);
		}

		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="contentType"></param>
		/// <param name="statusCode"></param>
		/// <param name="eTag"></param>
		/// <param name="lastModified"></param>
		/// <param name="correlationID"></param>
		public static void Write(this HttpContext context, string text, string contentType, int statusCode, string eTag, string lastModified, string correlationID = null)
		{
			context.SetResponseHeaders(statusCode, contentType, eTag, lastModified, correlationID);
			context.Write(text.ToBytes());
		}

		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="contentType"></param>
		/// <param name="statusCode"></param>
		/// <param name="correlationID"></param>
		public static void Write(this HttpContext context, string text, string contentType, int statusCode, string correlationID = null)
		{
			context.Write(text, contentType, statusCode, null, null, correlationID);
		}

		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="contentType"></param>
		/// <param name="statusCode"></param>
		/// <param name="eTag"></param>
		/// <param name="lastModified"></param>
		/// <param name="correlationID"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static async Task WriteAsync(this HttpContext context, string text, string contentType, int statusCode, string eTag, string lastModified, string correlationID = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			context.SetResponseHeaders(statusCode, contentType, eTag, lastModified, correlationID);
			await context.WriteAsync(text.ToBytes().ToArraySegment(), cancellationToken).ConfigureAwait(false);
		}

		/// <summary>
		/// Writes the given text to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="text"></param>
		/// <param name="contentType"></param>
		/// <param name="statusCode"></param>
		/// <param name="correlationID"></param>
		public static Task WriteAsync(this HttpContext context, string text, string contentType = "text/html", int statusCode = 200, string correlationID = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			return context.WriteAsync(text, contentType, statusCode, null, null, correlationID, cancellationToken);
		}
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
		/// <param name="correlationID"></param>
		public static void Write(this HttpContext context, JToken json, Newtonsoft.Json.Formatting formatting, string eTag, string lastModified, string correlationID = null)
		{
			context.Write(json?.ToString(formatting) ?? "{}", "application/json", (int)HttpStatusCode.OK, eTag, lastModified, correlationID);
		}

		/// <summary>
		/// Writes the JSON to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="json"></param>
		/// <param name="formatting"></param>
		/// <param name="correlationID"></param>
		public static void Write(this HttpContext context, JToken json, Newtonsoft.Json.Formatting formatting = Newtonsoft.Json.Formatting.None, string correlationID = null)
		{
			context.Write(json, formatting, null, null, correlationID);
		}

		/// <summary>
		/// Writes the JSON to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="json"></param>
		/// <param name="formatting"></param>
		/// <param name="eTag"></param>
		/// <param name="lastModified"></param>
		/// <param name="correlationID"></param>
		public static Task WriteAsync(this HttpContext context, JToken json, Newtonsoft.Json.Formatting formatting, string eTag, string lastModified, string correlationID = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			return context.WriteAsync(json?.ToString(formatting) ?? "{}", "application/json", (int)HttpStatusCode.OK, eTag, lastModified, correlationID, cancellationToken);
		}

		/// <summary>
		/// Writes the JSON to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="json"></param>
		/// <param name="formatting"></param>
		/// <param name="correlationID"></param>
		public static Task WriteAsync(this HttpContext context, JToken json, Newtonsoft.Json.Formatting formatting = Newtonsoft.Json.Formatting.None, string correlationID = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			return context.WriteAsync(json, formatting, null, null, correlationID, cancellationToken);
		}

		/// <summary>
		/// Writes the JSON to the response body
		/// </summary>
		/// <param name="context"></param>
		/// <param name="json"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpContext context, JToken json, CancellationToken cancellationToken)
		{
			return context.WriteAsync(json, Newtonsoft.Json.Formatting.None, null, cancellationToken);
		}
		#endregion

		#region Show HTTP Error as HTML
		static string GetHttpErrorHtml(this HttpContext context, int statusCode, string message, string type, string correlationID = null, string stack = null, bool showStack = true)
		{
			var html = "<!DOCTYPE html>\r\n" +
				$"<html xmlns=\"http://www.w3.org/1999/xhtml\">\r\n" +
				$"<head><title>Error {statusCode}</title></head>\r\n<body>\r\n" +
				$"<h1>HTTP {statusCode} - {message.Replace("<", "&lt;").Replace(">", "&gt;")}</h1>\r\n" +
				$"<hr/>\r\n" +
				$"<div>Type: {type} {(!string.IsNullOrWhiteSpace(correlationID) ? " - Correlation ID: " + correlationID : "")}</div>\r\n";
			if (!string.IsNullOrWhiteSpace(stack) && showStack)
				html += $"<div><br/>Stack:</div>\r\n<blockquote>{stack.Replace("<", "&lt;").Replace(">", "&gt;").Replace("\n", "<br/>").Replace("\r", "").Replace("\t", "")}</blockquote>\r\n";
			html += "</body>\r\n</html>";
			return html;
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
		public static void ShowHttpError(this HttpContext context, int statusCode, string message, string type, string correlationID = null, string stack = null, bool showStack = true)
		{
			statusCode = statusCode < 1 ? (int)HttpStatusCode.InternalServerError : statusCode;
			context.Clear();
			context.Write(context.GetHttpErrorHtml(statusCode, message, type, correlationID, stack, showStack), "text/html", statusCode, correlationID);
			if (message.IsContains("potentially dangerous"))
				context.Response.End();
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
		/// <param name="cancellationToken"></param>
		public static async Task ShowHttpErrorAsync(this HttpContext context, int statusCode, string message, string type, string correlationID = null, string stack = null, bool showStack = true, CancellationToken cancellationToken = default(CancellationToken))
		{
			statusCode = statusCode < 1 ? (int)HttpStatusCode.InternalServerError : statusCode;
			context.Clear();
			await context.WriteAsync(context.GetHttpErrorHtml(statusCode, message, type, correlationID, stack, showStack), "text/html", statusCode, correlationID, cancellationToken).ConfigureAwait(false);
			if (message.IsContains("potentially dangerous"))
				context.Response.End();
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
		/// <param name="cancellationToken"></param>
		public static Task ShowHttpErrorAsync(this HttpContext context, int statusCode, string message, string type, string correlationID, Exception ex, bool showStack = true, CancellationToken cancellationToken = default(CancellationToken))
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
			return context.ShowHttpErrorAsync(statusCode, message, type, correlationID, stack, showStack, cancellationToken);
		}
		#endregion

		#region Write HTTP Error as JSON
		static JObject GetHttpErrorJson(this HttpContext context, int statusCode, string message, string type, string correlationID = null, JObject stack = null, bool showStack = true)
		{
			var json = new JObject()
			{
				{ "Message", message },
				{ "Type", type },
				{ "Code", statusCode }
			};

			if (!string.IsNullOrWhiteSpace(correlationID))
				json["CorrelationID"] = correlationID;

			if (stack != null && showStack)
				json["Stack"] = stack;

			return json;
		}

		/// <summary>
		/// Writes HTTP error as JSON
		/// </summary>
		/// <param name="context"></param>
		/// <param name="statusCode"></param>
		/// <param name="message"></param>
		/// <param name="type"></param>
		/// <param name="correlationID"></param>
		/// <param name="stack"></param>
		/// <param name="showStack"></param>
		public static void WriteHttpError(this HttpContext context, int statusCode, string message, string type, string correlationID = null, JObject stack = null, bool showStack = true)
		{
			statusCode = statusCode < 1 ? (int)HttpStatusCode.InternalServerError : statusCode;
			context.Clear();
			context.Write(context.GetHttpErrorJson(statusCode, message, type, correlationID, stack, showStack).ToString(Newtonsoft.Json.Formatting.Indented), "application/json", statusCode, correlationID);
		}

		/// <summary>
		/// Writes HTTP error as JSON
		/// </summary>
		/// <param name="context"></param>
		/// <param name="statusCode"></param>
		/// <param name="message"></param>
		/// <param name="type"></param>
		/// <param name="correlationID"></param>
		/// <param name="ex"></param>
		/// <param name="showStack"></param>
		public static void WriteHttpError(this HttpContext context, int statusCode, string message, string type, string correlationID, Exception ex, bool showStack = true)
		{
			JObject stack = null;
			if (ex != null && showStack)
			{
				stack = new JObject()
				{
					{ "Stack", ex.StackTrace }
				};
				var inners = new JArray();
				var counter = 1;
				var inner = ex.InnerException;
				while (inner != null)
				{
					inners.Add(new JObject()
					{
						{ $"Inner_{counter}", inner.StackTrace }
					});
					inner = inner.InnerException;
					counter++;
				}
				if (inners.Count > 0)
					stack["Inners"] = inners;
			}
			context.WriteHttpError(statusCode, message, type, correlationID, stack, showStack);
		}

		/// <summary>
		/// Writes HTTP error as JSON
		/// </summary>
		/// <param name="context"></param>
		/// <param name="statusCode"></param>
		/// <param name="message"></param>
		/// <param name="type"></param>
		/// <param name="correlationID"></param>
		/// <param name="stack"></param>
		/// <param name="showStack"></param>
		/// <param name="cancellationToken"></param>
		public static async Task WriteHttpErrorAsync(this HttpContext context, int statusCode, string message, string type, string correlationID = null, JObject stack = null, bool showStack = true, CancellationToken cancellationToken = default(CancellationToken))
		{
			statusCode = statusCode < 1 ? (int)HttpStatusCode.InternalServerError : statusCode;
			context.Clear();
			await context.WriteAsync(context.GetHttpErrorJson(statusCode, message, type, correlationID, stack, showStack).ToString(Newtonsoft.Json.Formatting.Indented), "application/json", statusCode, correlationID, cancellationToken).ConfigureAwait(false);
		}

		/// <summary>
		/// Writes HTTP error as JSON
		/// </summary>
		/// <param name="context"></param>
		/// <param name="statusCode"></param>
		/// <param name="message"></param>
		/// <param name="type"></param>
		/// <param name="correlationID"></param>
		/// <param name="ex"></param>
		/// <param name="showStack"></param>
		/// <param name="cancellationToken"></param>
		public static Task WriteHttpErrorAsync(this HttpContext context, int statusCode, string message, string type, string correlationID, Exception ex, bool showStack = true, CancellationToken cancellationToken = default(CancellationToken))
		{
			JObject stack = null;
			if (ex != null && showStack)
			{
				stack = new JObject()
				{
					{ "Stack", ex.StackTrace }
				};
				var inners = new JArray();
				var counter = 1;
				var inner = ex.InnerException;
				while (inner != null)
				{
					inners.Add(new JObject()
					{
						{ $"Inner_{counter}", inner.StackTrace }
					});
					inner = inner.InnerException;
					counter++;
				}
				if (inners.Count > 0)
					stack["Inners"] = inners;
			}
			return context.WriteHttpErrorAsync(statusCode, message, type, correlationID, stack, showStack, cancellationToken);
		}
		#endregion

		#region Add & Get session's item
		/// <summary>
		/// Adds an item into ASP.NET Core Session
		/// </summary>
		/// <param name="session"></param>
		/// <param name="key"></param>
		/// <param name="value"></param>
		public static void Add(this ISession session, string key, object value)
		{
			if (!string.IsNullOrWhiteSpace(key))
				try
				{
					session.Set(key, Helper.Serialize(value));
				}
				catch (Exception ex)
				{
					Logger.Log<ISession>(LogLevel.Debug, LogLevel.Warning, $"Cannot add object into session: {ex.Message}", ex);
				}
		}

		/// <summary>
		/// Gets an item from ASP.NET Core Session
		/// </summary>
		/// <param name="session"></param>
		/// <param name="key"></param>
		/// <returns></returns>
		public static object Get(this ISession session, string key)
		{
			return !string.IsNullOrWhiteSpace(key)
				? session.TryGetValue(key, out byte[] value)
					? Helper.Deserialize(value)
					: null
				: null;
		}

		/// <summary>
		/// Gets an item from ASP.NET Core Session
		/// </summary>
		/// <param name="session"></param>
		/// <param name="key"></param>
		/// <returns></returns>
		public static T Get<T>(this ISession session, string key)
		{
			return !string.IsNullOrWhiteSpace(key)
				? session.TryGetValue(key, out byte[] value)
					? Helper.Deserialize<T>(value)
					: default(T)
				: default(T);
		}

		/// <summary>
		/// Checks to see the key is existed in ASP.NET Core Session or not
		/// </summary>
		/// <param name="session"></param>
		/// <param name="key"></param>
		/// <returns></returns>
		public static bool ContainsKey(this ISession session, string key)
		{
			return !string.IsNullOrWhiteSpace(key)
				? session.Keys.FirstOrDefault(k => k.IsEquals(key)) != null
				: false;
		}
		#endregion

		#region Wrap a WebSocket connection of ASP.NET Core into WebSocket component
		/// <summary>
		/// Wrap a WebSocket connection of ASP.NET Core
		/// </summary>
		/// <param name="websocket"></param>
		/// <param name="context">The working context of ASP.NET Core</param>
		/// <param name="whenIsNotWebSocketRequest">Action to run when the request is not WebSocket request</param>
		/// <returns></returns>
		public static async Task WrapAsync(this WebSocket websocket, HttpContext context, Action<HttpContext> whenIsNotWebSocketRequest = null)
		{
			if (context.WebSockets.IsWebSocketRequest)
			{
				var webSocket = await context.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false);
				var remoteEndPoint = new IPEndPoint(context.Connection.RemoteIpAddress, context.Connection.RemotePort);
				var localEndPoint = new IPEndPoint(context.Connection.LocalIpAddress, context.Connection.LocalPort);
				await websocket.WrapAsync(webSocket, context.GetRequestUri(), remoteEndPoint, localEndPoint).ConfigureAwait(false);
			}
			else
				whenIsNotWebSocketRequest?.Invoke(context);
		}

		/// <summary>
		/// Wrap a WebSocket connection of ASP.NET Core
		/// </summary>
		/// <param name="websocket"></param>
		/// <param name="context">The working context of ASP.NET Core</param>
		/// <param name="whenIsNotWebSocketRequest">Action to run when the request is not WebSocket request</param>
		/// <returns></returns>
		public static Task WrapWebSocketAsync(this WebSocket websocket, HttpContext context, Action<HttpContext> whenIsNotWebSocketRequest = null)
		{
			return websocket.WrapAsync(context, whenIsNotWebSocketRequest);
		}
		#endregion

	}
}