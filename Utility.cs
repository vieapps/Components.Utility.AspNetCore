#region Related components
using System;
using System.Linq;
using System.Net;
using System.IO;
using System.Data;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;

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

		#region HTTP Response extensions
		/// <summary>
		/// Writes the given text to the response body (UTF-8 encoding will be used)
		/// </summary>
		/// <param name="response"></param>
		/// <param name="text"></param>
		public static void Write(this HttpResponse response, string text)
		{
			var data = text.ToBytes();
			response.Body.Write(data, 0, data.Length);
		}

		/// <summary>
		/// Writes the array of bytes to HttpResponse Output Stream
		/// </summary>
		/// <param name="response"></param>
		/// <param name="data"></param>
		/// <param name="offset"></param>
		/// <param name="count"></param>
		public static void Write(this HttpResponse response, byte[] data, int offset = 0, int count = 0)
		{
			response.Body.Write(data, offset > -1 ? offset : 0, count > 0 ? count : data.Length);
		}

		/// <summary>
		/// Writes the array segment of bytes to HttpResponse Output Stream
		/// </summary>
		/// <param name="response"></param>
		/// <param name="data"></param>
		/// <returns></returns>
		public static void Write(this HttpResponse response, ArraySegment<byte> data)
		{
			response.Body.Write(data.Array, data.Offset, data.Count);
		}

		/// <summary>
		/// Writes the array of bytes to HttpResponse Output Stream
		/// </summary>
		/// <param name="response"></param>
		/// <param name="data"></param>
		/// <param name="offset"></param>
		/// <param name="count"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpResponse response, byte[] data, int offset = 0, int count = 0, CancellationToken cancellationToken = default(CancellationToken))
		{
			return response.Body.WriteAsync(data, offset > -1 ? offset : 0, count > 0 ? count : data.Length, cancellationToken);
		}

		/// <summary>
		/// Writes the array segment of bytes to HttpResponse Output Stream
		/// </summary>
		/// <param name="response"></param>
		/// <param name="data"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteAsync(this HttpResponse response, ArraySegment<byte> data, CancellationToken cancellationToken = default(CancellationToken))
		{
			return response.Body.WriteAsync(data.Array, data.Offset, data.Count, cancellationToken);
		}

		/// <summary>
		/// Sends all currently buffered output to the client
		/// </summary>
		/// <param name="response"></param>
		public static void Flush(this HttpResponse response)
		{
			response.Body.Flush();
		}

		/// <summary>
		/// Asynchronously sends all currently buffered output to the client
		/// </summary>
		/// <param name="response"></param>
		/// <param name="cancellationToken"></param>
		public static Task FlushAsync(this HttpResponse response, CancellationToken cancellationToken = default(CancellationToken))
		{
			return response.Body.FlushAsync(cancellationToken);
		}

		/// <summary>
		/// Sends all currently buffered output to the client, closes the response stream
		/// </summary>
		/// <param name="response"></param>
		public static void End(this HttpResponse response)
		{
			response.Body.Close();
		}
		#endregion

		#region Write a file to HTTP output stream directly
		internal static long MinSmallFileSize = 1024 * 40;                             // 40 KB
		internal static long MaxSmallFileSize = 1024 * 1024 * 2;                // 02 MB

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

		static string GetRequestETag(HttpContext context)
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
		/// Writes the content of the file directly to output stream
		/// </summary>
		/// <param name="context"></param>
		/// <param name="filePath">The path to file</param>
		/// <param name="contentType">The MIME type</param>
		/// <param name="contentDisposition">The string that presents name of attachment file, let it empty/null for writting showing/displaying (not for downloading attachment file)</param>
		/// <param name="eTag">The entity tag</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static async Task WriteFileToOutputAsync(this HttpContext context, string filePath, string contentType, string eTag = null, string contentDisposition = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			await context.WriteFileToOutputAsync(new FileInfo(filePath), contentType, eTag, contentDisposition, cancellationToken).ConfigureAwait(false);
		}

		/// <summary>
		/// Writes the content of the file directly to output stream
		/// </summary>
		/// <param name="context"></param>
		/// <param name="fileInfo">The information of the file</param>
		/// <param name="contentType">The MIME type</param>
		/// <param name="contentDisposition">The string that presents name of attachment file, let it empty/null for writting showing/displaying (not for downloading attachment file)</param>
		/// <param name="eTag">The entity tag</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static async Task WriteFileToOutputAsync(this HttpContext context, FileInfo fileInfo, string contentType, string eTag = null, string contentDisposition = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			if (fileInfo == null || !fileInfo.Exists)
				throw new FileNotFoundException("Not found" + (fileInfo != null ? " [" + fileInfo.Name + "]" : ""));

			using (var stream = new FileStream(fileInfo.FullName, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true))
			{
				await context.WriteStreamToOutputAsync(stream, contentType, eTag, fileInfo.LastWriteTime.ToHttpString(), contentDisposition, 0, cancellationToken).ConfigureAwait(false);
			}
		}

		/// <summary>
		/// Writes the binary data directly to output stream
		/// </summary>
		/// <param name="context"></param>
		/// <param name="data">The data to write</param>
		/// <param name="contentType">The MIME type</param>
		/// <param name="eTag">The entity tag</param>
		/// <param name="lastModified">The last-modified time in HTTP date-time format</param>
		/// <param name="contentDisposition">The string that presents name of attachment file, let it empty/null for writting showing/displaying (not for downloading attachment file)</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static async Task WriteDataToOutputAsync(this HttpContext context, byte[] data, string contentType, string eTag = null, string lastModified = null, string contentDisposition = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			using (var stream = new MemoryStream(data))
			{
				await context.WriteStreamToOutputAsync(stream, contentType, eTag, lastModified, contentDisposition, 0, cancellationToken).ConfigureAwait(false);
			}
		}

		/// <summary>
		/// Writes the stream directly to output stream
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
		public static async Task WriteStreamToOutputAsync(this HttpContext context, Stream stream, string contentType, string eTag = null, string lastModified = null, string contentDisposition = null, int blockSize = 0, CancellationToken cancellationToken = default(CancellationToken))
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
				var requestETag = AspNetCoreUtilityService.GetRequestETag(context);
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
			var headers = new List<string[]>();

			if (!string.IsNullOrWhiteSpace(lastModified))
				headers.Add(new string[] { "Last-Modified", lastModified });

			if (!string.IsNullOrWhiteSpace(eTag))
			{
				headers.Add(new string[] { "Accept-Ranges", "bytes" });
				headers.Add(new string[] { "ETag", "\"" + eTag + "\"" });
			}

			if (flushAsPartialContent && startBytes > -1)
				headers.Add(new string[] { "Content-Range", string.Format(" bytes {0}-{1}/{2}", startBytes, endBytes, totalBytes) });

			headers.Add(new string[] { "Content-Length", ((endBytes - startBytes) + 1).ToString() });

			if (!string.IsNullOrWhiteSpace(contentDisposition))
				headers.Add(new string[] { "Content-Disposition", "Attachment; Filename=\"" + contentDisposition + "\"" });

			// flush headers to HttpResponse output stream
			try
			{
				context.Response.ContentType = contentType;

				// status code of partial content
				if (flushAsPartialContent)
					context.Response.StatusCode = (int)HttpStatusCode.PartialContent;

				headers.ForEach(header => context.Response.Headers.Add(header[0], header[1]));
			}
			/*
			catch (HttpException ex)
			{
				var isDisconnected = ex.Message.Contains("0x800704CD") || ex.Message.Contains("0x800703E3") || ex.Message.Contains("The remote host closed the connection");
				if (!isDisconnected)
					throw ex;
			}
			*/
			catch (Exception)
			{
				throw;
			}

			// write small file directly to output stream
			if (!flushAsPartialContent && totalBytes <= AspNetCoreUtilityService.MaxSmallFileSize)
				try
				{
					var isDisconnected = false;
					var data = new byte[totalBytes];
					var readBytes = await stream.ReadAsync(data, 0, (int)totalBytes, cancellationToken).ConfigureAwait(false);
					try
					{
						await context.Response.WriteAsync(data, 0, readBytes, cancellationToken).ConfigureAwait(false);
					}
					catch (OperationCanceledException)
					{
						isDisconnected = true;
					}
					/*
					catch (HttpException ex)
					{
						isDisconnected = ex.Message.Contains("0x800704CD") || ex.Message.Contains("0x800703E3") || ex.Message.Contains("The remote host closed the connection");
						if (!isDisconnected)
							throw ex;
					}
					*/
					catch (Exception ex)
					{
						throw ex;
					}

					// flush the written buffer to client and update cache
					if (!isDisconnected)
						try
						{
							await context.Response.FlushAsync(cancellationToken).ConfigureAwait(false);
						}
						catch (Exception)
						{
							throw;
						}
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
				var isDisconnected = false;
				var readBlocks = 0;
				while (readBlocks < totalBlocks)
				{
					// the client is still connected
					try
					{
						var buffer = new byte[packSize];
						var readBytes = await stream.ReadAsync(buffer, 0, packSize, cancellationToken).ConfigureAwait(false);
						if (readBytes > 0)
						{
							// write data to output stream
							try
							{
								await context.Response.WriteAsync(buffer, 0, readBytes, cancellationToken).ConfigureAwait(false);
							}
							catch (OperationCanceledException)
							{
								isDisconnected = true;
								break;
							}
							/*
							catch (HttpException ex)
							{
								isDisconnected = ex.Message.Contains("0x800704CD") || ex.Message.Contains("0x800703E3") || ex.Message.Contains("The remote host closed the connection");
								if (!isDisconnected)
									throw ex;
								else
									break;
							}
							*/
							catch (Exception)
							{
								throw;
							}

							// flush the written buffer to client
							if (!isDisconnected)
								try
								{
									await context.Response.FlushAsync(cancellationToken).ConfigureAwait(false);
								}
								catch (Exception ex)
								{
									throw ex;
								}
						}
						readBlocks++;
					}
					catch (Exception ex)
					{
						throw ex;
					}
				}
			}
		}
		#endregion

		#region Write a data-set as Excel document to HTTP output stream directly
		/// <summary>
		/// Writes a data-set as Excel document to HTTP output stream directly
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
				await context.WriteStreamToOutputAsync(stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", null, null, filename, TextFileReader.BufferSize, cancellationToken).ConfigureAwait(false);
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

		#region Write a text content to HTTP output stream
		/// <summary>
		/// Gets the approriate headers
		/// </summary>
		/// <param name="context"></param>
		/// <param name="contentLength"></param>
		/// <param name="contentType"></param>
		/// <param name="contentEncoding"></param>
		/// <param name="eTag"></param>
		/// <param name="lastModified"></param>
		/// <param name="correlationID"></param>
		/// <returns></returns>
		public static Dictionary<string, string> GetHeaders(this HttpContext context, int contentLength, string contentType, string contentEncoding = null, string eTag = null, string lastModified = null, string correlationID = null)
		{
			var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
			{
				{ "Server", "VIEApps NGX" },
				{ "Content-Length", $"{contentLength}" },
				{ "Content-Type", $"{contentType}; charset=utf-8" }
			};

			if (!string.IsNullOrWhiteSpace(contentEncoding))
				headers.Add("Content-Encoding", contentEncoding);

			if (!string.IsNullOrWhiteSpace(eTag) && !string.IsNullOrWhiteSpace(lastModified))
			{
				headers.Add("ETag", "\"" + eTag + "\"");
				headers.Add("Last-Modified", lastModified);
			}

			if (context.Items.ContainsKey("Stopwatch"))
			{
				(context.Items["Stopwatch"] as Stopwatch).Stop();
				var executionTimes = (context.Items["Stopwatch"] as Stopwatch).GetElapsedTimes();
				headers.Add("X-Execution-Times", executionTimes);
			}

			if (!string.IsNullOrWhiteSpace(correlationID))
				headers.Add("X-Correlation-ID", correlationID);

			return headers;
		}

		/// <summary>
		/// Writes a string content to HTTP output stream
		/// </summary>
		/// <param name="context"></param>
		/// <param name="content"></param>
		/// <param name="contentType"></param>
		/// <param name="statusCode"></param>
		/// <param name="eTag"></param>
		/// <param name="lastModified"></param>
		/// <param name="correlationID"></param>
		public static void Write(this HttpContext context, string content, string contentType, int statusCode, string eTag, string lastModified, string correlationID = null)
		{
			var data = content.ToBytes();
			var contentEncoding = context.Request.Headers["Accept-Encoding"].First();
			if (contentEncoding.IsEquals("*") || contentEncoding.IsContains("deflate"))
			{
				contentEncoding = "deflate";
				data = data.Compress(contentEncoding);
			}
			else if (contentEncoding.IsContains("gzip"))
			{
				contentEncoding = "gzip";
				data = data.Compress(contentEncoding);
			}

			// write headers
			var headers = context.GetHeaders(data.Length, contentType, contentEncoding, eTag, lastModified, correlationID);
			headers.ForEach(kvp => context.Response.Headers.Add(kvp.Key, kvp.Value));

			// write details
			context.Response.StatusCode = statusCode;
			context.Response.Write(data);
		}

		/// <summary>
		/// Writes a string content to HTTP output stream
		/// </summary>
		/// <param name="context"></param>
		/// <param name="content"></param>
		/// <param name="contentType"></param>
		/// <param name="statusCode"></param>
		/// <param name="correlationID"></param>
		public static void Write(this HttpContext context, string content, string contentType, int statusCode, string correlationID = null)
		{
			context.Write(content, contentType, statusCode, null, null, correlationID);
		}

		/// <summary>
		/// Writes a string content to HTTP output stream
		/// </summary>
		/// <param name="context"></param>
		/// <param name="content"></param>
		/// <param name="contentType"></param>
		/// <param name="statusCode"></param>
		/// <param name="eTag"></param>
		/// <param name="lastModified"></param>
		/// <param name="correlationID"></param>
		public static async Task WriteAsync(this HttpContext context, string content, string contentType, int statusCode, string eTag, string lastModified, string correlationID = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			var data = content.ToBytes();
			var contentEncoding = context.Request.Headers["Accept-Encoding"].First();
			if (contentEncoding.IsEquals("*") || contentEncoding.IsContains("deflate"))
			{
				contentEncoding = "deflate";
				data = data.Compress(contentEncoding);
			}
			else if (contentEncoding.IsContains("gzip"))
			{
				contentEncoding = "gzip";
				data = data.Compress(contentEncoding);
			}

			// write headers
			var headers = context.GetHeaders(data.Length, contentType, contentEncoding, eTag, lastModified, correlationID);
			headers.ForEach(kvp => context.Response.Headers.Add(kvp.Key, kvp.Value));

			// write details
			context.Response.StatusCode = statusCode;
			await context.Response.WriteAsync(data.ToArraySegment(), cancellationToken).ConfigureAwait(false);
		}

		/// <summary>
		/// Writes a string content to HTTP output stream
		/// </summary>
		/// <param name="context"></param>
		/// <param name="content"></param>
		/// <param name="contentType"></param>
		/// <param name="statusCode"></param>
		/// <param name="correlationID"></param>
		public static Task WriteAsync(this HttpContext context, string content, string contentType = "text/html", int statusCode = 200, string correlationID = null, CancellationToken cancellationToken = default(CancellationToken))
		{
			return context.WriteAsync(content, contentType, statusCode, null, null, correlationID, cancellationToken);
		}
		#endregion

		#region Show HTTP Errors
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
		/// Show HTTP error
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
			context.Write(context.GetHttpErrorHtml(statusCode, message, type, correlationID, stack, showStack), "text/html", statusCode, correlationID);
			if (message.IsContains("potentially dangerous"))
				context.Response.End();
		}

		/// <summary>
		/// Show HTTP error
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
		/// Show HTTP error
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
			await context.WriteAsync(context.GetHttpErrorHtml(statusCode, message, type, correlationID, stack, showStack), "text/html", statusCode, correlationID, cancellationToken).ConfigureAwait(false);
			if (message.IsContains("potentially dangerous"))
				context.Response.End();
		}

		/// <summary>
		/// Show HTTP error
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

		#region Working with request URI
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
			var query = new Dictionary<string, string>(QueryHelpers.ParseQuery(uri.Query).ToDictionary(kvp => kvp.Key, kvp => kvp.Value.First(), StringComparer.OrdinalIgnoreCase));
			onCompleted?.Invoke(query);
			return query;
		}
		#endregion

		#region Wrap a WebSocket connection of ASP.NET Core into WebSocket component
		/// <summary>
		/// Wrap a WebSocket connection of ASP.NET Core into WebSocket component
		/// </summary>
		/// <param name="websocket"></param>
		/// <param name="context">The working context of ASP.NET Core</param>
		/// <returns></returns>
		public static async Task WrapAsync(this WebSocket websocket, HttpContext context)
		{
			if (context.WebSockets.IsWebSocketRequest)
			{
				var webSocket = await context.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false);
				var requestUri = context.GetRequestUri();
				var remoteEndPoint = new IPEndPoint(context.Connection.RemoteIpAddress, context.Connection.RemotePort);
				var localEndPoint = new IPEndPoint(context.Connection.LocalIpAddress, context.Connection.LocalPort);
				await websocket.WrapAsync(webSocket, requestUri, remoteEndPoint, localEndPoint).ConfigureAwait(false);
			}
		}

		/// <summary>
		/// Wrap a WebSocket connection of ASP.NET Core into WebSocket component
		/// </summary>
		/// <param name="websocket"></param>
		/// <param name="context">The working context of ASP.NET Core</param>
		/// <returns></returns>
		public static Task WrapWebSocketAsync(this WebSocket websocket, HttpContext context)
		{
			return websocket.WrapAsync(context);
		}
		#endregion

		#region Working with session items
		/// <summary>
		/// Adds an item into ASP.NET Core Session
		/// </summary>
		/// <param name="session"></param>
		/// <param name="key"></param>
		/// <param name="value"></param>
		public static void Add(this ISession session, string key, object value)
		{
			if (!string.IsNullOrWhiteSpace(key) && value != null)
				session.Set(key, Helper.Serialize(value));
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
		#endregion

	}
}