using org.bouncycastle.asn1.x500;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.crmf
{

				
	public class CertTemplate : ASN1Object
	{
		private ASN1Sequence seq;

		private ASN1Integer version;
		private ASN1Integer serialNumber;
		private AlgorithmIdentifier signingAlg;
		private X500Name issuer;
		private OptionalValidity validity;
		private X500Name subject;
		private SubjectPublicKeyInfo publicKey;
		private DERBitString issuerUID;
		private DERBitString subjectUID;
		private Extensions extensions;

		private CertTemplate(ASN1Sequence seq)
		{
			this.seq = seq;

			Enumeration en = seq.getObjects();
			while (en.hasMoreElements())
			{
				ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

				switch (tObj.getTagNo())
				{
				case 0:
					version = ASN1Integer.getInstance(tObj, false);
					break;
				case 1:
					serialNumber = ASN1Integer.getInstance(tObj, false);
					break;
				case 2:
					signingAlg = AlgorithmIdentifier.getInstance(tObj, false);
					break;
				case 3:
					issuer = X500Name.getInstance(tObj, true); // CHOICE
					break;
				case 4:
					validity = OptionalValidity.getInstance(ASN1Sequence.getInstance(tObj, false));
					break;
				case 5:
					subject = X500Name.getInstance(tObj, true); // CHOICE
					break;
				case 6:
					publicKey = SubjectPublicKeyInfo.getInstance(tObj, false);
					break;
				case 7:
					issuerUID = DERBitString.getInstance(tObj, false);
					break;
				case 8:
					subjectUID = DERBitString.getInstance(tObj, false);
					break;
				case 9:
					extensions = Extensions.getInstance(tObj, false);
					break;
				default:
					throw new IllegalArgumentException("unknown tag: " + tObj.getTagNo());
				}
			}
		}

		public static CertTemplate getInstance(object o)
		{
			if (o is CertTemplate)
			{
				return (CertTemplate)o;
			}
			else if (o != null)
			{
				return new CertTemplate(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		/// <summary>
		/// Return Version - -1 if not set.
		/// </summary>
		/// <returns> Version value. </returns>
		public virtual int getVersion()
		{
			if (version != null)
			{
				return version.getValue().intValue();
			}

			return -1;
		}

		public virtual ASN1Integer getSerialNumber()
		{
			return serialNumber;
		}

		public virtual AlgorithmIdentifier getSigningAlg()
		{
			return signingAlg;
		}

		public virtual X500Name getIssuer()
		{
			return issuer;
		}

		public virtual OptionalValidity getValidity()
		{
			return validity;
		}

		public virtual X500Name getSubject()
		{
			return subject;
		}

		public virtual SubjectPublicKeyInfo getPublicKey()
		{
			return publicKey;
		}

		public virtual DERBitString getIssuerUID()
		{
			return issuerUID;
		}

		public virtual DERBitString getSubjectUID()
		{
			return subjectUID;
		}

		public virtual Extensions getExtensions()
		{
			return extensions;
		}

		/// <summary>
		/// <pre>
		///  CertTemplate ::= SEQUENCE {
		///      version      [0] Version               OPTIONAL,
		///      serialNumber [1] INTEGER               OPTIONAL,
		///      signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
		///      issuer       [3] Name                  OPTIONAL,
		///      validity     [4] OptionalValidity      OPTIONAL,
		///      subject      [5] Name                  OPTIONAL,
		///      publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
		///      issuerUID    [7] UniqueIdentifier      OPTIONAL,
		///      subjectUID   [8] UniqueIdentifier      OPTIONAL,
		///      extensions   [9] Extensions            OPTIONAL }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return seq;
		}
	}

}