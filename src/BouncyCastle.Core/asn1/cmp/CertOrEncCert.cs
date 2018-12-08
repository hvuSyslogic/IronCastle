using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmp
{
	using EncryptedValue = org.bouncycastle.asn1.crmf.EncryptedValue;

	public class CertOrEncCert : ASN1Object, ASN1Choice
	{
		private CMPCertificate certificate;
		private EncryptedValue encryptedCert;

		private CertOrEncCert(ASN1TaggedObject tagged)
		{
			if (tagged.getTagNo() == 0)
			{
				certificate = CMPCertificate.getInstance(tagged.getObject());
			}
			else if (tagged.getTagNo() == 1)
			{
				encryptedCert = EncryptedValue.getInstance(tagged.getObject());
			}
			else
			{
				throw new IllegalArgumentException("unknown tag: " + tagged.getTagNo());
			}
		}

		public static CertOrEncCert getInstance(object o)
		{
			if (o is CertOrEncCert)
			{
				return (CertOrEncCert)o;
			}

			if (o is ASN1TaggedObject)
			{
				return new CertOrEncCert((ASN1TaggedObject)o);
			}

			return null;
		}

		public CertOrEncCert(CMPCertificate certificate)
		{
			if (certificate == null)
			{
				throw new IllegalArgumentException("'certificate' cannot be null");
			}

			this.certificate = certificate;
		}

		public CertOrEncCert(EncryptedValue encryptedCert)
		{
			if (encryptedCert == null)
			{
				throw new IllegalArgumentException("'encryptedCert' cannot be null");
			}

			this.encryptedCert = encryptedCert;
		}

		public virtual CMPCertificate getCertificate()
		{
			return certificate;
		}

		public virtual EncryptedValue getEncryptedCert()
		{
			return encryptedCert;
		}

		/// <summary>
		/// <pre>
		/// CertOrEncCert ::= CHOICE {
		///                      certificate     [0] CMPCertificate,
		///                      encryptedCert   [1] EncryptedValue
		///           }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			if (certificate != null)
			{
				return new DERTaggedObject(true, 0, certificate);
			}

			return new DERTaggedObject(true, 1, encryptedCert);
		}
	}

}