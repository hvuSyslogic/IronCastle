using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.cms
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using Attribute = org.bouncycastle.asn1.cms.Attribute;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using CMSAlgorithmProtection = org.bouncycastle.asn1.cms.CMSAlgorithmProtection;
	using CMSAttributes = org.bouncycastle.asn1.cms.CMSAttributes;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// Default authenticated attributes generator.
	/// </summary>
	public class DefaultAuthenticatedAttributeTableGenerator : CMSAttributeTableGenerator
	{
		private readonly Hashtable table;

		/// <summary>
		/// Initialise to use all defaults
		/// </summary>
		public DefaultAuthenticatedAttributeTableGenerator()
		{
			table = new Hashtable();
		}

		/// <summary>
		/// Initialise with some extra attributes or overrides.
		/// </summary>
		/// <param name="attributeTable"> initial attribute table to use. </param>
		public DefaultAuthenticatedAttributeTableGenerator(AttributeTable attributeTable)
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
		/// normally include contentType and messageDigest. If the constructor
		/// using an AttributeTable was used, entries in it for contentType and
		/// messageDigest will override the generated ones.
		/// </summary>
		/// <param name="parameters"> source parameters for table generation.
		/// </param>
		/// <returns> a filled in Hashtable of attributes. </returns>
		public virtual Hashtable createStandardAttributeTable(Map parameters)
		{
			Hashtable std = new Hashtable();

			for (Enumeration en = table.keys(); en.hasMoreElements();)
			{
				object key = en.nextElement();

				std.put(key, table.get(key));
			}

			if (!std.containsKey(CMSAttributes_Fields.contentType))
			{
				ASN1ObjectIdentifier contentType = ASN1ObjectIdentifier.getInstance(parameters.get(CMSAttributeTableGenerator_Fields.CONTENT_TYPE));
				Attribute attr = new Attribute(CMSAttributes_Fields.contentType, new DERSet(contentType));
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
				Attribute attr = new Attribute(CMSAttributes_Fields.cmsAlgorithmProtect, new DERSet(new CMSAlgorithmProtection((AlgorithmIdentifier)parameters.get(CMSAttributeTableGenerator_Fields.DIGEST_ALGORITHM_IDENTIFIER), CMSAlgorithmProtection.MAC, (AlgorithmIdentifier)parameters.get(CMSAttributeTableGenerator_Fields.MAC_ALGORITHM_IDENTIFIER))));
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
	}

}