using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	public class V2Form : ASN1Object
	{
		internal GeneralNames issuerName;
		internal IssuerSerial baseCertificateID;
		internal ObjectDigestInfo objectDigestInfo;

		public static V2Form getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static V2Form getInstance(object obj)
		{
			if (obj is V2Form)
			{
				return (V2Form)obj;
			}
			else if (obj != null)
			{
				return new V2Form(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public V2Form(GeneralNames issuerName) : this(issuerName, null, null)
		{
		}

		public V2Form(GeneralNames issuerName, IssuerSerial baseCertificateID) : this(issuerName, baseCertificateID, null)
		{
		}

		public V2Form(GeneralNames issuerName, ObjectDigestInfo objectDigestInfo) : this(issuerName, null, objectDigestInfo)
		{
		}

		public V2Form(GeneralNames issuerName, IssuerSerial baseCertificateID, ObjectDigestInfo objectDigestInfo)
		{
			this.issuerName = issuerName;
			this.baseCertificateID = baseCertificateID;
			this.objectDigestInfo = objectDigestInfo;
		}

		/// @deprecated use getInstance(). 
		public V2Form(ASN1Sequence seq)
		{
			if (seq.size() > 3)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			int index = 0;

			if (!(seq.getObjectAt(0) is ASN1TaggedObject))
			{
				index++;
				this.issuerName = GeneralNames.getInstance(seq.getObjectAt(0));
			}

			for (int i = index; i != seq.size(); i++)
			{
				ASN1TaggedObject o = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
				if (o.getTagNo() == 0)
				{
					baseCertificateID = IssuerSerial.getInstance(o, false);
				}
				else if (o.getTagNo() == 1)
				{
					objectDigestInfo = ObjectDigestInfo.getInstance(o, false);
				}
				else
				{
					throw new IllegalArgumentException("Bad tag number: " + o.getTagNo());
				}
			}
		}

		public virtual GeneralNames getIssuerName()
		{
			return issuerName;
		}

		public virtual IssuerSerial getBaseCertificateID()
		{
			return baseCertificateID;
		}

		public virtual ObjectDigestInfo getObjectDigestInfo()
		{
			return objectDigestInfo;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		///  V2Form ::= SEQUENCE {
		///       issuerName            GeneralNames  OPTIONAL,
		///       baseCertificateID     [0] IssuerSerial  OPTIONAL,
		///       objectDigestInfo      [1] ObjectDigestInfo  OPTIONAL
		///         -- issuerName MUST be present in this profile
		///         -- baseCertificateID and objectDigestInfo MUST NOT
		///         -- be present in this profile
		///  }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (issuerName != null)
			{
				v.add(issuerName);
			}

			if (baseCertificateID != null)
			{
				v.add(new DERTaggedObject(false, 0, baseCertificateID));
			}

			if (objectDigestInfo != null)
			{
				v.add(new DERTaggedObject(false, 1, objectDigestInfo));
			}

			return new DERSequence(v);
		}
	}

}