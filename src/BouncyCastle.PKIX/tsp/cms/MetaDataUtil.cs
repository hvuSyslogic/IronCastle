using org.bouncycastle.asn1;

namespace org.bouncycastle.tsp.cms
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1String = org.bouncycastle.asn1.ASN1String;
	using Attributes = org.bouncycastle.asn1.cms.Attributes;
	using MetaData = org.bouncycastle.asn1.cms.MetaData;
	using CMSException = org.bouncycastle.cms.CMSException;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;

	public class MetaDataUtil
	{
		private readonly MetaData metaData;

		public MetaDataUtil(MetaData metaData)
		{
			this.metaData = metaData;
		}

		public virtual void initialiseMessageImprintDigestCalculator(DigestCalculator calculator)
		{
			if (metaData != null && metaData.isHashProtected())
			{
				try
				{
					calculator.getOutputStream().write(metaData.getEncoded(ASN1Encoding_Fields.DER));
				}
				catch (IOException e)
				{
					throw new CMSException("unable to initialise calculator from metaData: " + e.Message, e);
				}
			}
		}

		public virtual string getFileName()
		{
			if (metaData != null)
			{
				return convertString(metaData.getFileName());
			}

			return null;
		}

		public virtual string getMediaType()
		{
			if (metaData != null)
			{
				return convertString(metaData.getMediaType());
			}

			return null;
		}

		public virtual Attributes getOtherMetaData()
		{
			if (metaData != null)
			{
				return metaData.getOtherMetaData();
			}

			return null;
		}

		private string convertString(ASN1String s)
		{
			if (s != null)
			{
				return s.ToString();
			}

			return null;
		}
	}

}