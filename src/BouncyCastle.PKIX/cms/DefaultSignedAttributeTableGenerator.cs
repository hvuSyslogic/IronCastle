using org.bouncycastle.asn1.cms;

using System;

namespace org.bouncycastle.cms
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using Attribute = org.bouncycastle.asn1.cms.Attribute;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using CMSAlgorithmProtection = org.bouncycastle.asn1.cms.CMSAlgorithmProtection;
	using CMSAttributes = org.bouncycastle.asn1.cms.CMSAttributes;
	using Time = org.bouncycastle.asn1.cms.Time;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// Default signed attributes generator.
	/// </summary>
	public class DefaultSignedAttributeTableGenerator : CMSAttributeTableGenerator
	{
		private readonly Hashtable table;

		/// <summary>
		/// Initialise to use all defaults
		/// </summary>
		public DefaultSignedAttributeTableGenerator()
		{
			table = new Hashtable();
		}

		/// <summary>
		/// Initialise with some extra attributes or overrides.
		/// </summary>
		/// <param name="attributeTable"> initial attribute table to use. </param>
		public DefaultSignedAttributeTableGenerator(AttributeTable attributeTable)
		{
			if (attributeTable != null)
			{
				table = attributeTable.toHashtable();
			}
			else
			{
				table = new Hashtable();
			}
		}

		/// <summary>
		/// Create a standard attribute table from the passed in parameters - this will
		/// normally include contentType, signingTime, messageDigest, and CMS algorithm protection.
		/// If the constructor using an AttributeTable was used, entries in it for contentType, signingTime, and
		/// messageDigest will override the generated ones.
		/// </summary>
		/// <param name="parameters"> source parameters for table generation.
		/// </param>
		/// <returns> a filled in Hashtable of attributes. </returns>
		public virtual Hashtable createStandardAttributeTable(Map parameters)
		{
			Hashtable std = copyHashTable(table);

			if (!std.containsKey(CMSAttributes_Fields.contentType))
			{
				ASN1ObjectIdentifier contentType = ASN1ObjectIdentifier.getInstance(parameters.get(CMSAttributeTableGenerator_Fields.CONTENT_TYPE));

				// contentType will be null if we're trying to generate a counter signature.
				if (contentType != null)
				{
					Attribute attr = new Attribute(CMSAttributes_Fields.contentType, new DERSet(contentType));
					std.put(attr.getAttrType(), attr);
				}
			}

			if (!std.containsKey(CMSAttributes_Fields.signingTime))
			{
				DateTime signingTime = DateTime.Now;
				Attribute attr = new Attribute(CMSAttributes_Fields.signingTime, new DERSet(new Time(signingTime)));
				std.put(attr.getAttrType(), attr);
			}

			if (!std.containsKey(CMSAttributes_Fields.messageDigest))
			{
				byte[] messageDigest = (byte[])parameters.get(CMSAttributeTableGenerator_Fields.DIGEST);
				Attribute attr = new Attribute(CMSAttributes_Fields.messageDigest, new DERSet(new DEROctetString(messageDigest)));
				std.put(attr.getAttrType(), attr);
			}

			if (!std.contains(CMSAttributes_Fields.cmsAlgorithmProtect))
			{
				Attribute attr = new Attribute(CMSAttributes_Fields.cmsAlgorithmProtect, new DERSet(new CMSAlgorithmProtection((AlgorithmIdentifier)parameters.get(CMSAttributeTableGenerator_Fields.DIGEST_ALGORITHM_IDENTIFIER), CMSAlgorithmProtection.SIGNATURE, (AlgorithmIdentifier)parameters.get(CMSAttributeTableGenerator_Fields.SIGNATURE_ALGORITHM_IDENTIFIER))));
				std.put(attr.getAttrType(), attr);
			}

			return std;
		}

		/// <param name="parameters"> source parameters </param>
		/// <returns> the populated attribute table </returns>
		public virtual AttributeTable getAttributes(Map parameters)
		{
			return new AttributeTable(createStandardAttributeTable(parameters));
		}

		private static Hashtable copyHashTable(Hashtable paramsMap)
		{
			Hashtable newTable = new Hashtable();

			Enumeration keys = paramsMap.keys();
			while (keys.hasMoreElements())
			{
				object key = keys.nextElement();
				newTable.put(key, paramsMap.get(key));
			}

			return newTable;
		}
	}

}