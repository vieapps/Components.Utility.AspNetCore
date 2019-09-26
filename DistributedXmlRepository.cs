using System;
using System.Linq;
using System.Xml.Linq;
using System.Collections.Generic;
using Microsoft.Extensions.Caching.Distributed;

namespace net.vieapps.Components.Utility
{
	/// <summary>
	/// Distributed XML repository for working with data-protection
	/// </summary>
	public class DistributedXmlRepository : Microsoft.AspNetCore.DataProtection.Repositories.IXmlRepository
	{
		readonly IDistributedCache _cache;
		readonly DistributedXmlRepositoryOptions _options;

		public DistributedXmlRepository(IDistributedCache cache, DistributedXmlRepositoryOptions options)
		{
			this._cache = cache;
			this._options = options;
		}

		XDocument Xml
		{
			get
			{
				try
				{
					var xml = this._cache.GetString(this._options.Key);
					return string.IsNullOrWhiteSpace(xml) ? new XDocument() : XDocument.Parse(xml);
				}
				catch
				{
					return new XDocument();
				}
			}
		}

		public IReadOnlyCollection<XElement> GetAllElements()
			=> this.Xml.Elements().ToList().AsReadOnly();

		public void StoreElement(XElement element, string friendlyName)
		{
			var xml = this.Xml;
			xml.Add(element);
			this._cache.SetString(this._options.Key, xml.ToString(SaveOptions.DisableFormatting), this._options.CacheOptions);
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