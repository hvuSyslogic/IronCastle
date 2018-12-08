using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.pkcs
{
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ContentInfo = org.bouncycastle.asn1.pkcs.ContentInfo;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using SafeBag = org.bouncycastle.asn1.pkcs.SafeBag;
	using CMSEncryptedData = org.bouncycastle.cms.CMSEncryptedData;
	using CMSException = org.bouncycastle.cms.CMSException;
	using InputDecryptorProvider = org.bouncycastle.@operator.InputDecryptorProvider;

	public class PKCS12SafeBagFactory
	{
		private ASN1Sequence safeBagSeq;

		public PKCS12SafeBagFactory(ContentInfo info)
		{
			if (info.getContentType().Equals(PKCSObjectIdentifiers_Fields.encryptedData))
			{
				throw new IllegalArgumentException("encryptedData requires constructor with decryptor.");
			}

			this.safeBagSeq = ASN1Sequence.getInstance(ASN1OctetString.getInstance(info.getContent()).getOctets());
		}

		public PKCS12SafeBagFactory(ContentInfo info, InputDecryptorProvider inputDecryptorProvider)
		{
			if (info.getContentType().Equals(PKCSObjectIdentifiers_Fields.encryptedData))
			{
				CMSEncryptedData encData = new CMSEncryptedData(ContentInfo.getInstance(info));

				try
				{
					this.safeBagSeq = ASN1Sequence.getInstance(encData.getContent(inputDecryptorProvider));
				}
				catch (CMSException e)
				{
					throw new PKCSException("unable to extract data: " + e.Message, e);
				}
				return;
			}

			throw new IllegalArgumentException("encryptedData requires constructor with decryptor.");
		}

		public virtual PKCS12SafeBag[] getSafeBags()
		{
			PKCS12SafeBag[] safeBags = new PKCS12SafeBag[safeBagSeq.size()];

			for (int i = 0; i != safeBagSeq.size(); i++)
			{
				safeBags[i] = new PKCS12SafeBag(SafeBag.getInstance(safeBagSeq.getObjectAt(i)));
			}

			return safeBags;
		}
	}

}