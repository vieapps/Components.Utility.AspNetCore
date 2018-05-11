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
			=> !string.IsNullOrWhiteSpace(key)
				? session.TryGetValue(key, out byte[] value)
					? Helper.Deserialize(value)
					: null
				: null;

		/// <summary>
		/// Gets an item from ASP.NET Core Session
		/// </summary>
		/// <param name="session"></param>
		/// <param name="key"></param>
		/// <returns></returns>
		public static T Get<T>(this ISession session, string key) 
			=> !string.IsNullOrWhiteSpace(key)
				? session.TryGetValue(key, out byte[] value)
					? Helper.Deserialize<T>(value)
					: default(T)
				: default(T);

		/// <summary>
		/// Checks to see the key is existed in ASP.NET Core Session or not
		/// </summary>
		/// <param name="session"></param>
		/// <param name="key"></param>
		/// <returns></returns>
		public static bool ContainsKey(this ISession session, string key) 
			=> !string.IsNullOrWhiteSpace(key)
				? session.Keys.FirstOrDefault(k => k.IsEquals(key)) != null
				: false;
		#endregion

		#region To name & value collection
		/// <summary>
		/// Converts this dictionary to collection of name and value
		/// </summary>
		/// <param name="dictionary"></param>
		/// <returns></returns>
		public static NameValueCollection ToNameValueCollection(this IDictionary<string, StringValues> dictionary)
		{
			var nvCollection = new NameValueCollection();
			dictionary.ForEach(kvp => nvCollection[kvp.Key] = kvp.Value);
			return nvCollection;
		}

		/// <summary>
		/// Converts this query string to collection of name and value
		/// </summary>
		/// <param name="queryString"></param>
		/// <returns></returns>
		public static NameValueCollection ToNameValueCollection(this QueryString queryString) => QueryHelpers.ParseQuery(queryString.ToUriComponent()).ToNameValueCollection();
		#endregion

	}
}