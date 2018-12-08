namespace org.bouncycastle.asn1.x509
{
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;

	/// <summary>
	/// The TBSCertificate object.
	/// <pre>
	/// TBSCertificate ::= SEQUENCE {
	///      version          [ 0 ]  Version DEFAULT v1(0),
	///      serialNumber            CertificateSerialNumber,
	///      signature               AlgorithmIdentifier,
	///      issuer                  Name,
	///      validity                Validity,
	///      subject                 Name,
	///      subjectPublicKeyInfo    SubjectPublicKeyInfo,
	///      issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
	///      subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
	///      extensions        [ 3 ] Extensions OPTIONAL
	///      }
	/// </pre>
	/// <para>
	/// Note: issuerUniqueID and subjectUniqueID are both deprecated by the IETF. This class
	/// will parse them, but you really shouldn't be creating new ones.
	/// </para>
	/// </summary>
	/// @deprecated use TBSCertificate 
	public class TBSCertificateStructure : ASN1Object, X509ObjectIdentifiers, PKCSObjectIdentifiers
	{
		internal ASN1Sequence seq;

		internal ASN1Integer version;
		internal ASN1Integer serialNumber;
		internal AlgorithmIdentifier signature;
		internal X500Name issuer;
		internal Time startDate, endDate;
		internal X500Name subject;
		internal SubjectPublicKeyInfo subjectPublicKeyInfo;
		internal DERBitString issuerUniqueId;
		internal DERBitString subjectUniqueId;
		internal X509Extensions extensions;

		public static TBSCertificateStructure getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static TBSCertificateStructure getInstance(object obj)
		{
			if (obj is TBSCertificateStructure)
			{
				return (TBSCertificateStructure)obj;
			}
			else if (obj != null)
			{
				return new TBSCertificateStructure(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public TBSCertificateStructure(ASN1Sequence seq)
		{
			int seqStart = 0;

			this.seq = seq;

			//
			// some certficates don't include a version number - we assume v1
			//
			if (seq.getObjectAt(0) is DERTaggedObject)
			{
				version = ASN1Integer.getInstance((ASN1TaggedObject)seq.getObjectAt(0), true);
			}
			else
			{
				seqStart = -1; // field 0 is missing!
				version = new ASN1Integer(0);
			}

			serialNumber = ASN1Integer.getInstance(seq.getObjectAt(seqStart + 1));

			signature = AlgorithmIdentifier.getInstance(seq.getObjectAt(seqStart + 2));
			issuer = X500Name.getInstance(seq.getObjectAt(seqStart + 3));

			//
			// before and after dates
			//
			ASN1Sequence dates = (ASN1Sequence)seq.getObjectAt(seqStart + 4);

			startDate = Time.getInstance(dates.getObjectAt(0));
			endDate = Time.getInstance(dates.getObjectAt(1));

			subject = X500Name.getInstance(seq.getObjectAt(seqStart + 5));

			//
			// public key info.
			//
			subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(seqStart + 6));

			for (int extras = seq.size() - (seqStart + 6) - 1; extras > 0; extras--)
			{
				DERTaggedObject extra = (DERTaggedObject)seq.getObjectAt(seqStart + 6 + extras);

				switch (extra.getTagNo())
				{
				case 1:
					issuerUniqueId = DERBitString.getInstance(extra, false);
					break;
				case 2:
					subjectUniqueId = DERBitString.getInstance(extra, false);
					break;
				case 3:
					extensions = X509Extensions.getInstance(extra);
				break;
				}
			}
		}

		public virtual int getVersion()
		{
			return version.getValue().intValue() + 1;
		}

		public virtual ASN1Integer getVersionNumber()
		{
			return version;
		}

		public virtual ASN1Integer getSerialNumber()
		{
			return serialNumber;
		}

		public virtual AlgorithmIdentifier getSignature()
		{
			return signature;
		}

		public virtual X500Name getIssuer()
		{
			return issuer;
		}

		public virtual Time getStartDate()
		{
			return startDate;
		}

		public virtual Time getEndDate()
		{
			return endDate;
		}

		public virtual X500Name getSubject()
		{
			return subject;
		}

		public virtual SubjectPublicKeyInfo getSubjectPublicKeyInfo()
		{
			return subjectPublicKeyInfo;
		}

		public virtual DERBitString getIssuerUniqueId()
		{
			return issuerUniqueId;
		}

		public virtual DERBitString getSubjectUniqueId()
		{
			return subjectUniqueId;
		}

		public virtual X509Extensions getExtensions()
		{
			return extensions;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return seq;
		}
	}

}