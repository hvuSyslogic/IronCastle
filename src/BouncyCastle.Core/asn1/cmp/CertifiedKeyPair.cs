using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmp
{
	using EncryptedValue = org.bouncycastle.asn1.crmf.EncryptedValue;
	using PKIPublicationInfo = org.bouncycastle.asn1.crmf.PKIPublicationInfo;

	/// <summary>
	/// <pre>
	/// CertifiedKeyPair ::= SEQUENCE {
	///                                  certOrEncCert       CertOrEncCert,
	///                                  privateKey      [0] EncryptedValue      OPTIONAL,
	///                                  -- see [CRMF] for comment on encoding
	///                                  publicationInfo [1] PKIPublicationInfo  OPTIONAL
	///       }
	/// </pre>
	/// </summary>
	public class CertifiedKeyPair : ASN1Object
	{
		private CertOrEncCert certOrEncCert;
		private EncryptedValue privateKey;
		private PKIPublicationInfo publicationInfo;

		private CertifiedKeyPair(ASN1Sequence seq)
		{
			certOrEncCert = CertOrEncCert.getInstance(seq.getObjectAt(0));

			if (seq.size() >= 2)
			{
				if (seq.size() == 2)
				{
					ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
					if (tagged.getTagNo() == 0)
					{
						privateKey = EncryptedValue.getInstance(tagged.getObject());
					}
					else
					{
						publicationInfo = PKIPublicationInfo.getInstance(tagged.getObject());
					}
				}
				else
				{
					privateKey = EncryptedValue.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(1)).getObject());
					publicationInfo = PKIPublicationInfo.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(2)).getObject());
				}
			}
		}

		public static CertifiedKeyPair getInstance(object o)
		{
			if (o is CertifiedKeyPair)
			{
				return (CertifiedKeyPair)o;
			}

			if (o != null)
			{
				return new CertifiedKeyPair(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public CertifiedKeyPair(CertOrEncCert certOrEncCert) : this(certOrEncCert, null, null)
		{
		}

		public CertifiedKeyPair(CertOrEncCert certOrEncCert, EncryptedValue privateKey, PKIPublicationInfo publicationInfo)
		{
			if (certOrEncCert == null)
			{
				throw new IllegalArgumentException("'certOrEncCert' cannot be null");
			}

			this.certOrEncCert = certOrEncCert;
			this.privateKey = privateKey;
			this.publicationInfo = publicationInfo;
		}

		public virtual CertOrEncCert getCertOrEncCert()
		{
			return certOrEncCert;
		}

		public virtual EncryptedValue getPrivateKey()
		{
			return privateKey;
		}

		public virtual PKIPublicationInfo getPublicationInfo()
		{
			return publicationInfo;
		}

		/// <summary>
		/// Return the primitive representation of PKIPublicationInfo.
		/// </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(certOrEncCert);

			if (privateKey != null)
			{
				v.add(new DERTaggedObject(true, 0, privateKey));
			}

			if (publicationInfo != null)
			{
				v.add(new DERTaggedObject(true, 1, publicationInfo));
			}

			return new DERSequence(v);
		}
	}

}