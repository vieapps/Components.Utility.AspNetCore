#region Related components
using System;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Specialized;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Logging;
using net.vieapps.Components.Caching;
#endregion

namespace net.vieapps.Components.Utility
{
	/// <summary>
	/// Static servicing methods for working with ASP.NET Core collections
	/// </summary>
	public static partial class AspNetCoreCollectionService
	{
		/// <summary>
		/// Sets an object into this context items
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="context"></param>
		/// <param name="name"></param>
		/// <returns></returns>
		public static T SetItem<T>(this HttpContext context, string name, T value)
		{
			context.Items[name] = value;
			return value;
		}

		/// <summary>
		/// Gets an object from this context items
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="context"></param>
		/// <param name="name"></param>
		/// <returns></returns>
		public static bool TryGetItem<T>(this HttpContext context, string name, out T value)
		{
			value = default;
			if (context.Items.TryGetValue(name, out var val) && val is T tvalue)
			{
				value = tvalue;
				return true;
			}
			return false;
		}

		/// <summary>
		/// Gets an object from this context items
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="context"></param>
		/// <param name="name"></param>
		/// <returns></returns>
		public static T GetItem<T>(this HttpContext context, string name, T @default = default)
			=> context.TryGetItem<T>(name, out var value) ? value : @default;

		/// <summary>
		/// Gets an object from this context items
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="context"></param>
		/// <param name="name"></param>
		/// <returns></returns>
		public static T GetItem<T>(this StatusCodeContext context, string name, T @default = default)
			=> context.HttpContext.GetItem(name, @default);

		/// <summary>
		/// Removes an object from this context items
		/// </summary>
		/// <param name="context"></param>
		/// <param name="name"></param>
		/// <returns></returns>
		public static bool RemoveItem(this HttpContext context, string name)
			=> !string.IsNullOrWhiteSpace(name) && context.Items.Remove(name);

		/// <summary>
		/// Removes more objects from this context items
		/// </summary>
		/// <param name="context"></param>
		/// <param name="names"></param>
		/// <returns></returns>
		public static bool RemoveItems(this HttpContext context, IEnumerable<string> names)
		{
			var result = names?.Select(name => context.RemoveItem(name));
			return result != null && !result.Any(value => value == false);
		}

		/// <summary>
		/// Converts this dictionary of string values to dictionary of string
		/// </summary>
		/// <param name="dictionary"></param>
		/// <param name="onCompleted">The action to run before completed</param>
		/// <returns></returns>
		public static Dictionary<string, string> ToDictionary(this IDictionary<string, StringValues> dictionary, Action<Dictionary<string, string>> onCompleted = null)
		{
			var dict = dictionary.ToDictionary(kvp => kvp.Key.ToLower(), kvp => kvp.Value.Where(@string => @string != null).Select(@string => @string.AsciiDecode()).Join(","), StringComparer.OrdinalIgnoreCase);
			onCompleted?.Invoke(dict);
			return dict;
		}

		/// <summary>
		/// Converts this dictionary of string values to collection of name and value
		/// </summary>
		/// <param name="dictionary"></param>
		/// <param name="onCompleted">The action to run before completed</param>
		/// <returns></returns>
		public static NameValueCollection ToNameValueCollection(this IDictionary<string, StringValues> dictionary, Action<NameValueCollection> onCompleted = null)
		{
			var nvCollection = new NameValueCollection();
			dictionary.ToDictionary(dict => dict.ForEach(kvp => nvCollection[kvp.Key] = kvp.Value));
			onCompleted?.Invoke(nvCollection);
			return nvCollection;
		}

		/// <summary>
		/// Converts this header to a dictionary of string
		/// </summary>
		/// <param name="header"></param>
		/// <param name="onCompleted">The action to run before completed</param>
		/// <returns></returns>
		public static Dictionary<string, string> ToDictionary(this IHeaderDictionary header, Action<Dictionary<string, string>> onCompleted = null)
			=> (header as IDictionary<string, StringValues>).ToDictionary(onCompleted);

		/// <summary>
		/// Converts this header to collection of name and value
		/// </summary>
		/// <param name="header"></param>
		/// <param name="onCompleted">The action to run before completed</param>
		/// <returns></returns>
		public static NameValueCollection ToNameValueCollection(this IHeaderDictionary header, Action<NameValueCollection> onCompleted = null)
			=> (header as IDictionary<string, StringValues>).ToNameValueCollection(onCompleted);

		/// <summary>
		/// Converts this query string to a dictionary of string
		/// </summary>
		/// <param name="queryString"></param>
		/// <param name="onCompleted">The action to run before completed</param>
		/// <returns></returns>
		public static Dictionary<string, string> ToDictionary(this QueryString queryString, Action<Dictionary<string, string>> onCompleted = null)
			=> QueryHelpers.ParseQuery(queryString.ToUriComponent()).ToDictionary(onCompleted);

		/// <summary>
		/// Converts this query string to collection of name and value
		/// </summary>
		/// <param name="queryString"></param>
		/// <param name="onCompleted">The action to run before completed</param>
		/// <returns></returns>
		public static NameValueCollection ToNameValueCollection(this QueryString queryString, Action<NameValueCollection> onCompleted = null)
			=> QueryHelpers.ParseQuery(queryString.ToUriComponent()).ToNameValueCollection(onCompleted);
	}
}