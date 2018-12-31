using BouncyCastle.Core.Port;
using org.bouncycastle.asn1.x500;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

				
	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-10.2.4">RFC 5652</a>: IssuerAndSerialNumber object.
	/// <para>
	/// <pre>
	/// IssuerAndSerialNumber ::= SEQUENCE {
	///     issuer Name,
	///     serialNumber CertificateSerialNumber
	/// }
	/// 
	/// CertificateSerialNumber ::= INTEGER  -- See RFC 5280
	/// </pre>
	/// </para>
	/// </summary>
	public class IssuerAndSerialNumber : ASN1Object
	{
		private X500Name name;
		private ASN1Integer serialNumber;

		/// <summary>
		/// Return an IssuerAndSerialNumber object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="IssuerAndSerialNumber"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with IssuerAndSerialNumber structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static IssuerAndSerialNumber getInstance(object obj)
		{
			if (obj is IssuerAndSerialNumber)
			{
				return (IssuerAndSerialNumber)obj;
			}
			else if (obj != null)
			{
				return new IssuerAndSerialNumber(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// @deprecated  use getInstance() method. 
		public IssuerAndSerialNumber(ASN1Sequence seq)
		{
			this.name = X500Name.getInstance(seq.getObjectAt(0));
			this.serialNumber = (ASN1Integer)seq.getObjectAt(1);
		}

		public IssuerAndSerialNumber(Certificate certificate)
		{
			this.name = certificate.getIssuer();
			this.serialNumber = certificate.getSerialNumber();
		}

		/// @deprecated use constructor taking Certificate 
		public IssuerAndSerialNumber(X509CertificateStructure certificate)
		{
			this.name = certificate.getIssuer();
			this.serialNumber = certificate.getSerialNumber();
		}

		public IssuerAndSerialNumber(X500Name name, BigInteger serialNumber)
		{
			this.name = name;
			this.serialNumber = new ASN1Integer(serialNumber);
		}

		/// @deprecated use X500Name constructor 
		public IssuerAndSerialNumber(X509Name name, BigInteger serialNumber)
		{
			this.name = X500Name.getInstance(name);
			this.serialNumber = new ASN1Integer(serialNumber);
		}

		/// @deprecated use X500Name constructor 
		public IssuerAndSerialNumber(X509Name name, ASN1Integer serialNumber)
		{
			this.name = X500Name.getInstance(name);
			this.serialNumber = serialNumber;
		}

		public virtual X500Name getName()
		{
			return name;
		}

		public virtual ASN1Integer getSerialNumber()
		{
			return serialNumber;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(name);
			v.add(serialNumber);

			return new DERSequence(v);
		}
	}

}