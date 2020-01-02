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

		protected XDocument GetXDocument()
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

		public IReadOnlyCollection<XElement> GetAllElements()
			=> this.GetXDocument().Elements().ToList().AsReadOnly();

		public void StoreElement(XElement element, string friendlyName)
		{
			XDocument document;
			try
			{
				document = this.GetXDocument();
				document.Add(element);
			}
			catch
			{
				this._cache.Remove(this._options.Key);
				document = new XDocument();
				document.Add(element);
			}
			this._cache.SetString(this._options.Key, document.ToString(SaveOptions.DisableFormatting), this._options.CacheOptions);
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