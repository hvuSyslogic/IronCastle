using BouncyCastle.Core.Port;
using org.bouncycastle.asn1.x500;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	
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
	public class TBSCertificate : ASN1Object
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
		internal Extensions extensions;

		public static TBSCertificate getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static TBSCertificate getInstance(object obj)
		{
			if (obj is TBSCertificate)
			{
				return (TBSCertificate)obj;
			}
			else if (obj != null)
			{
				return new TBSCertificate(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private TBSCertificate(ASN1Sequence seq)
		{
			int seqStart = 0;

			this.seq = seq;

			//
			// some certficates don't include a version number - we assume v1
			//
			if (seq.getObjectAt(0) is ASN1TaggedObject)
			{
				version = ASN1Integer.getInstance((ASN1TaggedObject)seq.getObjectAt(0), true);
			}
			else
			{
				seqStart = -1; // field 0 is missing!
				version = new ASN1Integer(0);
			}

			bool isV1 = false;
			bool isV2 = false;

			if (version.getValue().Equals(BigInteger.valueOf(0)))
			{
				isV1 = true;
			}
			else if (version.getValue().Equals(BigInteger.valueOf(1)))
			{
				isV2 = true;
			}
			else if (!version.getValue().Equals(BigInteger.valueOf(2)))
			{
				throw new IllegalArgumentException("version number not recognised");
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

			int extras = seq.size() - (seqStart + 6) - 1;
			if (extras != 0 && isV1)
			{
				throw new IllegalArgumentException("version 1 certificate contains extra data");
			}

			while (extras > 0)
			{
				ASN1TaggedObject extra = (ASN1TaggedObject)seq.getObjectAt(seqStart + 6 + extras);

				switch (extra.getTagNo())
				{
				case 1:
					issuerUniqueId = DERBitString.getInstance(extra, false);
					break;
				case 2:
					subjectUniqueId = DERBitString.getInstance(extra, false);
					break;
				case 3:
					if (isV2)
					{
						throw new IllegalArgumentException("version 2 certificate cannot contain extensions");
					}
					extensions = Extensions.getInstance(ASN1Sequence.getInstance(extra, true));
					break;
				default:
					throw new IllegalArgumentException("Unknown tag encountered in structure: " + extra.getTagNo());
				}
				extras--;
			}
		}

		public virtual int getVersionNumber()
		{
			return version.getValue().intValue() + 1;
		}

		public virtual ASN1Integer getVersion()
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

		public virtual Extensions getExtensions()
		{
			return extensions;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return seq;
		}
	}

}