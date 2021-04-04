#region Related components
using System;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Specialized;
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
					session.Set(key.ToLower(), Helper.Serialize(value));
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
			=> !string.IsNullOrWhiteSpace(key) && session.TryGetValue(key.ToLower(), out var value)
				? Helper.Deserialize(value)
				: null;

		/// <summary>
		/// Gets an item from ASP.NET Core Session
		/// </summary>
		/// <param name="session"></param>
		/// <param name="key"></param>
		/// <returns></returns>
		public static T Get<T>(this ISession session, string key) 
			=> !string.IsNullOrWhiteSpace(key) &&  session.TryGetValue(key.ToLower(), out var value)
				? Helper.Deserialize<T>(value)
				: default;

		/// <summary>
		/// Checks to see the key is existed in ASP.NET Core Session or not
		/// </summary>
		/// <param name="session"></param>
		/// <param name="key"></param>
		/// <returns></returns>
		public static bool ContainsKey(this ISession session, string key) 
			=> !string.IsNullOrWhiteSpace(key) && session.Keys.FirstOrDefault(k => k.IsEquals(key.ToLower())) != null;

		/// <summary>
		/// Sets an object into this context items
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="context"></param>
		/// <param name="name"></param>
		/// <returns></returns>
		public static void SetItem<T>(this HttpContext context, string name, T value)
			=> context.Items[name] = value;

		/// <summary>
		/// Gets an object from this context items
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="context"></param>
		/// <param name="name"></param>
		/// <returns></returns>
		public static T GetItem<T>(this HttpContext context, string name)
			=> context.Items.TryGetValue(name, out var value) && value is T val
				? val
				: default;

		/// <summary>
		/// Converts this dictionary of string values to collection of name and value
		/// </summary>
		/// <param name="dictionary"></param>
		/// <param name="onCompleted">The action to run before completed</param>
		/// <returns></returns>
		public static NameValueCollection ToNameValueCollection(this IDictionary<string, StringValues> dictionary, Action<NameValueCollection> onCompleted = null)
		{
			var nvCollection = new NameValueCollection();
			dictionary.ForEach(kvp => nvCollection[kvp.Key.ToLower()] = kvp.Value);
			onCompleted?.Invoke(nvCollection);
			return nvCollection;
		}

		/// <summary>
		/// Converts this query string to collection of name and value
		/// </summary>
		/// <param name="queryString"></param>
		/// <param name="onCompleted">The action to run before completed</param>
		/// <returns></returns>
		public static NameValueCollection ToNameValueCollection(this QueryString queryString, Action<NameValueCollection> onCompleted = null)
			=> QueryHelpers.ParseQuery(queryString.ToUriComponent()).ToNameValueCollection(onCompleted);

		/// <summary>
		/// Converts this dictionary of string values to dictinary of string
		/// </summary>
		/// <param name="dictionary"></param>
		/// <param name="onCompleted">The action to run before completed</param>
		/// <returns></returns>
		public static Dictionary<string, string> ToDictionary(this IDictionary<string, StringValues> dictionary, Action<Dictionary<string, string>> onCompleted = null)
		{
			var dict = dictionary.ToDictionary(kvp => kvp.Key, kvp => $"{kvp.Value}", StringComparer.OrdinalIgnoreCase);
			onCompleted?.Invoke(dict);
			return dict;
		}

		/// <summary>
		/// Converts this query string to a dictinary of string
		/// </summary>
		/// <param name="queryString"></param>
		/// <param name="onCompleted">The action to run before completed</param>
		/// <returns></returns>
		public static Dictionary<string, string> ToDictionary(this QueryString queryString, Action<Dictionary<string, string>> onCompleted = null)
			=> QueryHelpers.ParseQuery(queryString.ToUriComponent()).ToDictionary(onCompleted);

		/// <summary>
		/// Converts this header to a dictinary of string
		/// </summary>
		/// <param name="header"></param>
		/// <param name="onCompleted">The action to run before completed</param>
		/// <returns></returns>
		public static Dictionary<string, string> ToDictionary(this IHeaderDictionary header, Action<Dictionary<string, string>> onCompleted = null)
			=> (header as IDictionary<string, StringValues>).ToDictionary(onCompleted);
	}
}