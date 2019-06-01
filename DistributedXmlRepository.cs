using System;
using System.Linq;
using System.Xml.Linq;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;

namespace net.vieapps.Components.Utility
{
	/// <summary>
	/// Distributed XML repository for working with data-protection
	/// </summary>
	public class DistributedXmlRepository : IXmlRepository
	{
		readonly IDistributedCache _cache;
		readonly DistributedXmlRepositoryOptions _options;

		public DistributedXmlRepository(IDistributedCache cache, DistributedXmlRepositoryOptions options)
		{
			this._cache = cache;
			this._options = options;
		}

		public IReadOnlyCollection<XElement> GetAllElements()
		{
			var xml = this._cache.GetString(this._options.Key);
			return (xml == null ? new XDocument() : XDocument.Parse(xml)).Elements().ToList().AsReadOnly();
		}

		public void StoreElement(XElement element, string friendlyName)
		{
			var xml = this._cache.GetString(this._options.Key);
			var xdoc = xml == null ? new XDocument() : XDocument.Parse(xml);
			xdoc.Add(element);
			this._cache.SetString(this._options.Key, xdoc.ToString(SaveOptions.DisableFormatting), this._options.CacheOptions);
		}
	}

	/// <summary>
	/// Distributed XML repository options for working with data-protection
	/// </summary>
	public class DistributedXmlRepositoryOptions
	{
		public DistributedCacheEntryOptions CacheOptions { get; set; } = new DistributedCacheEntryOptions { AbsoluteExpiration = new DateTimeOffset(DateTime.Now.AddDays(2)) };

		public string Key { get; set; } = "DataProtection-Keys";
	}
}