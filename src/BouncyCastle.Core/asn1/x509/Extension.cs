using System.IO;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{


	/// <summary>
	/// an object for the elements in the X.509 V3 extension block.
	/// </summary>
	public class Extension : ASN1Object
	{
		/// <summary>
		/// Subject Directory Attributes
		/// </summary>
		public static readonly ASN1ObjectIdentifier subjectDirectoryAttributes = new ASN1ObjectIdentifier("2.5.29.9").intern();

		/// <summary>
		/// Subject Key Identifier 
		/// </summary>
		public static readonly ASN1ObjectIdentifier subjectKeyIdentifier = new ASN1ObjectIdentifier("2.5.29.14").intern();

		/// <summary>
		/// Key Usage 
		/// </summary>
		public static readonly ASN1ObjectIdentifier keyUsage = new ASN1ObjectIdentifier("2.5.29.15").intern();

		/// <summary>
		/// Private Key Usage Period 
		/// </summary>
		public static readonly ASN1ObjectIdentifier privateKeyUsagePeriod = new ASN1ObjectIdentifier("2.5.29.16").intern();

		/// <summary>
		/// Subject Alternative Name 
		/// </summary>
		public static readonly ASN1ObjectIdentifier subjectAlternativeName = new ASN1ObjectIdentifier("2.5.29.17").intern();

		/// <summary>
		/// Issuer Alternative Name 
		/// </summary>
		public static readonly ASN1ObjectIdentifier issuerAlternativeName = new ASN1ObjectIdentifier("2.5.29.18").intern();

		/// <summary>
		/// Basic Constraints 
		/// </summary>
		public static readonly ASN1ObjectIdentifier basicConstraints = new ASN1ObjectIdentifier("2.5.29.19").intern();

		/// <summary>
		/// CRL Number 
		/// </summary>
		public static readonly ASN1ObjectIdentifier cRLNumber = new ASN1ObjectIdentifier("2.5.29.20").intern();

		/// <summary>
		/// Reason code 
		/// </summary>
		public static readonly ASN1ObjectIdentifier reasonCode = new ASN1ObjectIdentifier("2.5.29.21").intern();

		/// <summary>
		/// Hold Instruction Code 
		/// </summary>
		public static readonly ASN1ObjectIdentifier instructionCode = new ASN1ObjectIdentifier("2.5.29.23").intern();

		/// <summary>
		/// Invalidity Date 
		/// </summary>
		public static readonly ASN1ObjectIdentifier invalidityDate = new ASN1ObjectIdentifier("2.5.29.24").intern();

		/// <summary>
		/// Delta CRL indicator 
		/// </summary>
		public static readonly ASN1ObjectIdentifier deltaCRLIndicator = new ASN1ObjectIdentifier("2.5.29.27").intern();

		/// <summary>
		/// Issuing Distribution Point 
		/// </summary>
		public static readonly ASN1ObjectIdentifier issuingDistributionPoint = new ASN1ObjectIdentifier("2.5.29.28").intern();

		/// <summary>
		/// Certificate Issuer 
		/// </summary>
		public static readonly ASN1ObjectIdentifier certificateIssuer = new ASN1ObjectIdentifier("2.5.29.29").intern();

		/// <summary>
		/// Name Constraints 
		/// </summary>
		public static readonly ASN1ObjectIdentifier nameConstraints = new ASN1ObjectIdentifier("2.5.29.30").intern();

		/// <summary>
		/// CRL Distribution Points 
		/// </summary>
		public static readonly ASN1ObjectIdentifier cRLDistributionPoints = new ASN1ObjectIdentifier("2.5.29.31").intern();

		/// <summary>
		/// Certificate Policies 
		/// </summary>
		public static readonly ASN1ObjectIdentifier certificatePolicies = new ASN1ObjectIdentifier("2.5.29.32").intern();

		/// <summary>
		/// Policy Mappings 
		/// </summary>
		public static readonly ASN1ObjectIdentifier policyMappings = new ASN1ObjectIdentifier("2.5.29.33").intern();

		/// <summary>
		/// Authority Key Identifier 
		/// </summary>
		public static readonly ASN1ObjectIdentifier authorityKeyIdentifier = new ASN1ObjectIdentifier("2.5.29.35").intern();

		/// <summary>
		/// Policy Constraints 
		/// </summary>
		public static readonly ASN1ObjectIdentifier policyConstraints = new ASN1ObjectIdentifier("2.5.29.36").intern();

		/// <summary>
		/// Extended Key Usage 
		/// </summary>
		public static readonly ASN1ObjectIdentifier extendedKeyUsage = new ASN1ObjectIdentifier("2.5.29.37").intern();

		/// <summary>
		/// Freshest CRL
		/// </summary>
		public static readonly ASN1ObjectIdentifier freshestCRL = new ASN1ObjectIdentifier("2.5.29.46").intern();

		/// <summary>
		/// Inhibit Any Policy
		/// </summary>
		public static readonly ASN1ObjectIdentifier inhibitAnyPolicy = new ASN1ObjectIdentifier("2.5.29.54").intern();

		/// <summary>
		/// Authority Info Access
		/// </summary>
		public static readonly ASN1ObjectIdentifier authorityInfoAccess = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.1").intern();

		/// <summary>
		/// Subject Info Access
		/// </summary>
		public static readonly ASN1ObjectIdentifier subjectInfoAccess = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.11").intern();

		/// <summary>
		/// Logo Type
		/// </summary>
		public static readonly ASN1ObjectIdentifier logoType = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.12").intern();

		/// <summary>
		/// BiometricInfo
		/// </summary>
		public static readonly ASN1ObjectIdentifier biometricInfo = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.2").intern();

		/// <summary>
		/// QCStatements
		/// </summary>
		public static readonly ASN1ObjectIdentifier qCStatements = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.3").intern();

		/// <summary>
		/// Audit identity extension in attribute certificates.
		/// </summary>
		public static readonly ASN1ObjectIdentifier auditIdentity = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.4").intern();

		/// <summary>
		/// NoRevAvail extension in attribute certificates.
		/// </summary>
		public static readonly ASN1ObjectIdentifier noRevAvail = new ASN1ObjectIdentifier("2.5.29.56").intern();

		/// <summary>
		/// TargetInformation extension in attribute certificates.
		/// </summary>
		public static readonly ASN1ObjectIdentifier targetInformation = new ASN1ObjectIdentifier("2.5.29.55").intern();

		/// <summary>
		/// Expired Certificates on CRL extension
		/// </summary>
		public static readonly ASN1ObjectIdentifier expiredCertsOnCRL = new ASN1ObjectIdentifier("2.5.29.60").intern();

		private ASN1ObjectIdentifier extnId;
		private bool critical;
		private ASN1OctetString value;

		public Extension(ASN1ObjectIdentifier extnId, ASN1Boolean critical, ASN1OctetString value) : this(extnId, critical.isTrue(), value)
		{
		}

		public Extension(ASN1ObjectIdentifier extnId, bool critical, byte[] value) : this(extnId, critical, new DEROctetString(value))
		{
		}

		public Extension(ASN1ObjectIdentifier extnId, bool critical, ASN1OctetString value)
		{
			this.extnId = extnId;
			this.critical = critical;
			this.value = value;
		}

		private Extension(ASN1Sequence seq)
		{
			if (seq.size() == 2)
			{
				this.extnId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
				this.critical = false;
				this.value = ASN1OctetString.getInstance(seq.getObjectAt(1));
			}
			else if (seq.size() == 3)
			{
				this.extnId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
				this.critical = ASN1Boolean.getInstance(seq.getObjectAt(1)).isTrue();
				this.value = ASN1OctetString.getInstance(seq.getObjectAt(2));
			}
			else
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}
		}

		public static Extension getInstance(object obj)
		{
			if (obj is Extension)
			{
				return (Extension)obj;
			}
			else if (obj != null)
			{
				return new Extension(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1ObjectIdentifier getExtnId()
		{
			return extnId;
		}

		public virtual bool isCritical()
		{
			return critical;
		}

		public virtual ASN1OctetString getExtnValue()
		{
			return value;
		}

		public virtual ASN1Encodable getParsedValue()
		{
			return convertValueToObject(this);
		}

		public override int GetHashCode()
		{
			if (this.isCritical())
			{
				return this.getExtnValue().GetHashCode() ^ this.getExtnId().GetHashCode();
			}

			return ~(this.getExtnValue().GetHashCode() ^ this.getExtnId().GetHashCode());
		}

		public override bool Equals(object o)
		{
			if (!(o is Extension))
			{
				return false;
			}

			Extension other = (Extension)o;

			return other.getExtnId().Equals(this.getExtnId()) && other.getExtnValue().Equals(this.getExtnValue()) && (other.isCritical() == this.isCritical());
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(extnId);

			if (critical)
			{
				v.add(ASN1Boolean.getInstance(true));
			}

			v.add(value);

			return new DERSequence(v);
		}

		/// <summary>
		/// Convert the value of the passed in extension to an object </summary>
		/// <param name="ext"> the extension to parse </param>
		/// <returns> the object the value string contains </returns>
		/// <exception cref="IllegalArgumentException"> if conversion is not possible </exception>
		private static ASN1Primitive convertValueToObject(Extension ext)
		{
			try
			{
				return ASN1Primitive.fromByteArray(ext.getExtnValue().getOctets());
			}
			catch (IOException e)
			{
				throw new IllegalArgumentException("can't convert extension: " + e);
			}
		}
	}

}