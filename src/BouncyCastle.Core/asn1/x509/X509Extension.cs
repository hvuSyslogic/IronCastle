using System.IO;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{


	/// <summary>
	/// an object for the elements in the X.509 V3 extension block. </summary>
	/// @deprecated use Extension 
	public class X509Extension
	{
		/// <summary>
		/// Subject Directory Attributes
		/// </summary>
		public static readonly ASN1ObjectIdentifier subjectDirectoryAttributes = new ASN1ObjectIdentifier("2.5.29.9");

		/// <summary>
		/// Subject Key Identifier 
		/// </summary>
		public static readonly ASN1ObjectIdentifier subjectKeyIdentifier = new ASN1ObjectIdentifier("2.5.29.14");

		/// <summary>
		/// Key Usage 
		/// </summary>
		public static readonly ASN1ObjectIdentifier keyUsage = new ASN1ObjectIdentifier("2.5.29.15");

		/// <summary>
		/// Private Key Usage Period 
		/// </summary>
		public static readonly ASN1ObjectIdentifier privateKeyUsagePeriod = new ASN1ObjectIdentifier("2.5.29.16");

		/// <summary>
		/// Subject Alternative Name 
		/// </summary>
		public static readonly ASN1ObjectIdentifier subjectAlternativeName = new ASN1ObjectIdentifier("2.5.29.17");

		/// <summary>
		/// Issuer Alternative Name 
		/// </summary>
		public static readonly ASN1ObjectIdentifier issuerAlternativeName = new ASN1ObjectIdentifier("2.5.29.18");

		/// <summary>
		/// Basic Constraints 
		/// </summary>
		public static readonly ASN1ObjectIdentifier basicConstraints = new ASN1ObjectIdentifier("2.5.29.19");

		/// <summary>
		/// CRL Number 
		/// </summary>
		public static readonly ASN1ObjectIdentifier cRLNumber = new ASN1ObjectIdentifier("2.5.29.20");

		/// <summary>
		/// Reason code 
		/// </summary>
		public static readonly ASN1ObjectIdentifier reasonCode = new ASN1ObjectIdentifier("2.5.29.21");

		/// <summary>
		/// Hold Instruction Code 
		/// </summary>
		public static readonly ASN1ObjectIdentifier instructionCode = new ASN1ObjectIdentifier("2.5.29.23");

		/// <summary>
		/// Invalidity Date 
		/// </summary>
		public static readonly ASN1ObjectIdentifier invalidityDate = new ASN1ObjectIdentifier("2.5.29.24");

		/// <summary>
		/// Delta CRL indicator 
		/// </summary>
		public static readonly ASN1ObjectIdentifier deltaCRLIndicator = new ASN1ObjectIdentifier("2.5.29.27");

		/// <summary>
		/// Issuing Distribution Point 
		/// </summary>
		public static readonly ASN1ObjectIdentifier issuingDistributionPoint = new ASN1ObjectIdentifier("2.5.29.28");

		/// <summary>
		/// Certificate Issuer 
		/// </summary>
		public static readonly ASN1ObjectIdentifier certificateIssuer = new ASN1ObjectIdentifier("2.5.29.29");

		/// <summary>
		/// Name Constraints 
		/// </summary>
		public static readonly ASN1ObjectIdentifier nameConstraints = new ASN1ObjectIdentifier("2.5.29.30");

		/// <summary>
		/// CRL Distribution Points 
		/// </summary>
		public static readonly ASN1ObjectIdentifier cRLDistributionPoints = new ASN1ObjectIdentifier("2.5.29.31");

		/// <summary>
		/// Certificate Policies 
		/// </summary>
		public static readonly ASN1ObjectIdentifier certificatePolicies = new ASN1ObjectIdentifier("2.5.29.32");

		/// <summary>
		/// Policy Mappings 
		/// </summary>
		public static readonly ASN1ObjectIdentifier policyMappings = new ASN1ObjectIdentifier("2.5.29.33");

		/// <summary>
		/// Authority Key Identifier 
		/// </summary>
		public static readonly ASN1ObjectIdentifier authorityKeyIdentifier = new ASN1ObjectIdentifier("2.5.29.35");

		/// <summary>
		/// Policy Constraints 
		/// </summary>
		public static readonly ASN1ObjectIdentifier policyConstraints = new ASN1ObjectIdentifier("2.5.29.36");

		/// <summary>
		/// Extended Key Usage 
		/// </summary>
		public static readonly ASN1ObjectIdentifier extendedKeyUsage = new ASN1ObjectIdentifier("2.5.29.37");

		/// <summary>
		/// Freshest CRL
		/// </summary>
		public static readonly ASN1ObjectIdentifier freshestCRL = new ASN1ObjectIdentifier("2.5.29.46");

		/// <summary>
		/// Inhibit Any Policy
		/// </summary>
		public static readonly ASN1ObjectIdentifier inhibitAnyPolicy = new ASN1ObjectIdentifier("2.5.29.54");

		/// <summary>
		/// Authority Info Access
		/// </summary>
		public static readonly ASN1ObjectIdentifier authorityInfoAccess = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.1");

		/// <summary>
		/// Subject Info Access
		/// </summary>
		public static readonly ASN1ObjectIdentifier subjectInfoAccess = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.11");

		/// <summary>
		/// Logo Type
		/// </summary>
		public static readonly ASN1ObjectIdentifier logoType = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.12");

		/// <summary>
		/// BiometricInfo
		/// </summary>
		public static readonly ASN1ObjectIdentifier biometricInfo = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.2");

		/// <summary>
		/// QCStatements
		/// </summary>
		public static readonly ASN1ObjectIdentifier qCStatements = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.3");

		/// <summary>
		/// Audit identity extension in attribute certificates.
		/// </summary>
		public static readonly ASN1ObjectIdentifier auditIdentity = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.4");

		/// <summary>
		/// NoRevAvail extension in attribute certificates.
		/// </summary>
		public static readonly ASN1ObjectIdentifier noRevAvail = new ASN1ObjectIdentifier("2.5.29.56");

		/// <summary>
		/// TargetInformation extension in attribute certificates.
		/// </summary>
		public static readonly ASN1ObjectIdentifier targetInformation = new ASN1ObjectIdentifier("2.5.29.55");

		internal bool critical;
		internal ASN1OctetString value;

		public X509Extension(ASN1Boolean critical, ASN1OctetString value)
		{
			this.critical = critical.isTrue();
			this.value = value;
		}

		public X509Extension(bool critical, ASN1OctetString value)
		{
			this.critical = critical;
			this.value = value;
		}

		public virtual bool isCritical()
		{
			return critical;
		}

		public virtual ASN1OctetString getValue()
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
				return this.getValue().GetHashCode();
			}

			return ~this.getValue().GetHashCode();
		}

		public override bool Equals(object o)
		{
			if (!(o is X509Extension))
			{
				return false;
			}

			X509Extension other = (X509Extension)o;

			return other.getValue().Equals(this.getValue()) && (other.isCritical() == this.isCritical());
		}

		/// <summary>
		/// Convert the value of the passed in extension to an object </summary>
		/// <param name="ext"> the extension to parse </param>
		/// <returns> the object the value string contains </returns>
		/// <exception cref="IllegalArgumentException"> if conversion is not possible </exception>
		public static ASN1Primitive convertValueToObject(X509Extension ext)
		{
			try
			{
				return ASN1Primitive.fromByteArray(ext.getValue().getOctets());
			}
			catch (IOException e)
			{
				throw new IllegalArgumentException("can't convert extension: " + e);
			}
		}
	}

}