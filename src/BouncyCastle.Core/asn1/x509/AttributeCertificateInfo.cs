using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	public class AttributeCertificateInfo : ASN1Object
	{
		private ASN1Integer version;
		private Holder holder;
		private AttCertIssuer issuer;
		private AlgorithmIdentifier signature;
		private ASN1Integer serialNumber;
		private AttCertValidityPeriod attrCertValidityPeriod;
		private ASN1Sequence attributes;
		private DERBitString issuerUniqueID;
		private Extensions extensions;

		public static AttributeCertificateInfo getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static AttributeCertificateInfo getInstance(object obj)
		{
			if (obj is AttributeCertificateInfo)
			{
				return (AttributeCertificateInfo)obj;
			}
			else if (obj != null)
			{
				return new AttributeCertificateInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private AttributeCertificateInfo(ASN1Sequence seq)
		{
			if (seq.size() < 6 || seq.size() > 9)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			int start;
			if (seq.getObjectAt(0) is ASN1Integer) // in version 1 certs version is DEFAULT  v1(0)
			{
				this.version = ASN1Integer.getInstance(seq.getObjectAt(0));
				start = 1;
			}
			else
			{
				this.version = new ASN1Integer(0);
				start = 0;
			}

			this.holder = Holder.getInstance(seq.getObjectAt(start));
			this.issuer = AttCertIssuer.getInstance(seq.getObjectAt(start + 1));
			this.signature = AlgorithmIdentifier.getInstance(seq.getObjectAt(start + 2));
			this.serialNumber = ASN1Integer.getInstance(seq.getObjectAt(start + 3));
			this.attrCertValidityPeriod = AttCertValidityPeriod.getInstance(seq.getObjectAt(start + 4));
			this.attributes = ASN1Sequence.getInstance(seq.getObjectAt(start + 5));

			for (int i = start + 6; i < seq.size(); i++)
			{
				ASN1Encodable obj = seq.getObjectAt(i);

				if (obj is DERBitString)
				{
					this.issuerUniqueID = DERBitString.getInstance(seq.getObjectAt(i));
				}
				else if (obj is ASN1Sequence || obj is Extensions)
				{
					this.extensions = Extensions.getInstance(seq.getObjectAt(i));
				}
			}
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual Holder getHolder()
		{
			return holder;
		}

		public virtual AttCertIssuer getIssuer()
		{
			return issuer;
		}

		public virtual AlgorithmIdentifier getSignature()
		{
			return signature;
		}

		public virtual ASN1Integer getSerialNumber()
		{
			return serialNumber;
		}

		public virtual AttCertValidityPeriod getAttrCertValidityPeriod()
		{
			return attrCertValidityPeriod;
		}

		public virtual ASN1Sequence getAttributes()
		{
			return attributes;
		}

		public virtual DERBitString getIssuerUniqueID()
		{
			return issuerUniqueID;
		}

		public virtual Extensions getExtensions()
		{
			return extensions;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		///  AttributeCertificateInfo ::= SEQUENCE {
		///       version              AttCertVersion -- version is v2,
		///       holder               Holder,
		///       issuer               AttCertIssuer,
		///       signature            AlgorithmIdentifier,
		///       serialNumber         CertificateSerialNumber,
		///       attrCertValidityPeriod   AttCertValidityPeriod,
		///       attributes           SEQUENCE OF Attribute,
		///       issuerUniqueID       UniqueIdentifier OPTIONAL,
		///       extensions           Extensions OPTIONAL
		///  }
		/// 
		///  AttCertVersion ::= INTEGER { v2(1) }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (version.getValue().intValue() != 0)
			{
				v.add(version);
			}
			v.add(holder);
			v.add(issuer);
			v.add(signature);
			v.add(serialNumber);
			v.add(attrCertValidityPeriod);
			v.add(attributes);

			if (issuerUniqueID != null)
			{
				v.add(issuerUniqueID);
			}

			if (extensions != null)
			{
				v.add(extensions);
			}

			return new DERSequence(v);
		}
	}

}