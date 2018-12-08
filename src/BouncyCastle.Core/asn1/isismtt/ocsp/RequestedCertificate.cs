using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.isismtt.ocsp
{

	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// ISIS-MTT-Optional: The certificate requested by the client by inserting the
	/// RetrieveIfAllowed extension in the request, will be returned in this
	/// extension.
	/// <para>
	/// ISIS-MTT-SigG: The signature act allows publishing certificates only then,
	/// when the certificate owner gives his explicit permission. Accordingly, there
	/// may be �nondownloadable� certificates, about which the responder must provide
	/// status information, but MUST NOT include them in the response. Clients may
	/// get therefore the following three kind of answers on a single request
	/// including the RetrieveIfAllowed extension:
	/// <ul>
	/// <li> a) the responder supports the extension and is allowed to publish the
	/// certificate: RequestedCertificate returned including the requested
	/// certificate
	/// <li>b) the responder supports the extension but is NOT allowed to publish
	/// the certificate: RequestedCertificate returned including an empty OCTET
	/// STRING
	/// <li>c) the responder does not support the extension: RequestedCertificate is
	/// not included in the response
	/// </ul>
	/// Clients requesting RetrieveIfAllowed MUST be able to handle these cases. If
	/// any of the OCTET STRING options is used, it MUST contain the DER encoding of
	/// the requested certificate.
	/// <pre>
	///            RequestedCertificate ::= CHOICE {
	///              Certificate Certificate,
	///              publicKeyCertificate [0] EXPLICIT OCTET STRING,
	///              attributeCertificate [1] EXPLICIT OCTET STRING
	///            }
	/// </pre>
	/// </para>
	/// </summary>
	public class RequestedCertificate : ASN1Object, ASN1Choice
	{
		public const int certificate = -1;
		public const int publicKeyCertificate = 0;
		public const int attributeCertificate = 1;

		private Certificate cert;
		private byte[] publicKeyCert;
		private byte[] attributeCert;

		public static RequestedCertificate getInstance(object obj)
		{
			if (obj == null || obj is RequestedCertificate)
			{
				return (RequestedCertificate)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new RequestedCertificate(Certificate.getInstance(obj));
			}
			if (obj is ASN1TaggedObject)
			{
				return new RequestedCertificate((ASN1TaggedObject)obj);
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		public static RequestedCertificate getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			if (!@explicit)
			{
				throw new IllegalArgumentException("choice item must be explicitly tagged");
			}

			return getInstance(obj.getObject());
		}

		private RequestedCertificate(ASN1TaggedObject tagged)
		{
			if (tagged.getTagNo() == publicKeyCertificate)
			{
				publicKeyCert = ASN1OctetString.getInstance(tagged, true).getOctets();
			}
			else if (tagged.getTagNo() == attributeCertificate)
			{
				attributeCert = ASN1OctetString.getInstance(tagged, true).getOctets();
			}
			else
			{
				throw new IllegalArgumentException("unknown tag number: " + tagged.getTagNo());
			}
		}

		/// <summary>
		/// Constructor from a given details.
		/// <para>
		/// Only one parameter can be given. All other must be <code>null</code>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="certificate">          Given as Certificate </param>
		public RequestedCertificate(Certificate certificate)
		{
			this.cert = certificate;
		}

		public RequestedCertificate(int type, byte[] certificateOctets) : this(new DERTaggedObject(type, new DEROctetString(certificateOctets)))
		{
		}

		public virtual int getType()
		{
			if (cert != null)
			{
				return certificate;
			}
			if (publicKeyCert != null)
			{
				return publicKeyCertificate;
			}
			return attributeCertificate;
		}

		public virtual byte[] getCertificateBytes()
		{
			if (cert != null)
			{
				try
				{
					return cert.getEncoded();
				}
				catch (IOException e)
				{
					throw new IllegalStateException("can't decode certificate: " + e);
				}
			}
			if (publicKeyCert != null)
			{
				return Arrays.clone(publicKeyCert);
			}
			return Arrays.clone(attributeCert);
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <para>
		/// Returns:
		/// <pre>
		///            RequestedCertificate ::= CHOICE {
		///              Certificate Certificate,
		///              publicKeyCertificate [0] EXPLICIT OCTET STRING,
		///              attributeCertificate [1] EXPLICIT OCTET STRING
		///            }
		/// </pre>
		/// 
		/// </para>
		/// </summary>
		/// <returns> a DERObject </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			if (publicKeyCert != null)
			{
				return new DERTaggedObject(0, new DEROctetString(publicKeyCert));
			}
			if (attributeCert != null)
			{
				return new DERTaggedObject(1, new DEROctetString(attributeCert));
			}
			return cert.toASN1Primitive();
		}
	}

}