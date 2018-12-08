using org.bouncycastle.asn1.crmf;
using org.bouncycastle.asn1.cms;

using System;

namespace org.bouncycastle.cert.crmf
{
	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using EnvelopedData = org.bouncycastle.asn1.cms.EnvelopedData;
	using CRMFObjectIdentifiers = org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
	using EncryptedKey = org.bouncycastle.asn1.crmf.EncryptedKey;
	using PKIArchiveOptions = org.bouncycastle.asn1.crmf.PKIArchiveOptions;
	using CMSEnvelopedData = org.bouncycastle.cms.CMSEnvelopedData;
	using CMSException = org.bouncycastle.cms.CMSException;

	/// <summary>
	/// Carrier for a PKIArchiveOptions structure.
	/// </summary>
	public class PKIArchiveControl : Control
	{
		public const int encryptedPrivKey = PKIArchiveOptions.encryptedPrivKey;
		public const int keyGenParameters = PKIArchiveOptions.keyGenParameters;
		public const int archiveRemGenPrivKey = PKIArchiveOptions.archiveRemGenPrivKey;

		private static readonly ASN1ObjectIdentifier type = CRMFObjectIdentifiers_Fields.id_regCtrl_pkiArchiveOptions;

		private readonly PKIArchiveOptions pkiArchiveOptions;

		/// <summary>
		/// Basic constructor - build from an PKIArchiveOptions structure.
		/// </summary>
		/// <param name="pkiArchiveOptions">  the ASN.1 structure that will underlie this control. </param>
		public PKIArchiveControl(PKIArchiveOptions pkiArchiveOptions)
		{
			this.pkiArchiveOptions = pkiArchiveOptions;
		}

		/// <summary>
		/// Return the type of this control.
		/// </summary>
		/// <returns> CRMFObjectIdentifiers.id_regCtrl_pkiArchiveOptions </returns>
		public virtual ASN1ObjectIdentifier getType()
		{
			return type;
		}

		/// <summary>
		/// Return the underlying ASN.1 object.
		/// </summary>
		/// <returns> a PKIArchiveOptions structure. </returns>
		public virtual ASN1Encodable getValue()
		{
			return pkiArchiveOptions;
		}

		/// <summary>
		/// Return the archive control type, one of: encryptedPrivKey,keyGenParameters,or archiveRemGenPrivKey.
		/// </summary>
		/// <returns> the archive control type. </returns>
		public virtual int getArchiveType()
		{
			return pkiArchiveOptions.getType();
		}

		/// <summary>
		/// Return whether this control contains enveloped data.
		/// </summary>
		/// <returns> true if the control contains enveloped data, false otherwise. </returns>
		public virtual bool isEnvelopedData()
		{
			EncryptedKey encKey = EncryptedKey.getInstance(pkiArchiveOptions.getValue());

			return !encKey.isEncryptedValue();
		}

		/// <summary>
		/// Return the enveloped data structure contained in this control.
		/// </summary>
		/// <returns> a CMSEnvelopedData object. </returns>
		public virtual CMSEnvelopedData getEnvelopedData()
		{
			try
			{
				EncryptedKey encKey = EncryptedKey.getInstance(pkiArchiveOptions.getValue());
				EnvelopedData data = EnvelopedData.getInstance(encKey.getValue());

				return new CMSEnvelopedData(new ContentInfo(CMSObjectIdentifiers_Fields.envelopedData, data));
			}
			catch (CMSException e)
			{
				throw new CRMFException("CMS parsing error: " + e.Message, e.InnerException);
			}
			catch (Exception e)
			{
				throw new CRMFException("CRMF parsing error: " + e.Message, e);
			}
		}
	}

}