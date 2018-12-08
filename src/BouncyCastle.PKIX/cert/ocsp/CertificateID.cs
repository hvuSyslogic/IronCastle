using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.cert.ocsp
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using CertID = org.bouncycastle.asn1.ocsp.CertID;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;

	public class CertificateID
	{
		public static readonly AlgorithmIdentifier HASH_SHA1 = new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE);

		private readonly CertID id;

		public CertificateID(CertID id)
		{
			if (id == null)
			{
				throw new IllegalArgumentException("'id' cannot be null");
			}
			this.id = id;
		}

		/// <summary>
		/// create from an issuer certificate and the serial number of the
		/// certificate it signed.
		/// </summary>
		/// <param name="issuerCert"> issuing certificate </param>
		/// <param name="number"> serial number
		/// </param>
		/// <exception cref="OCSPException"> if any problems occur creating the id fields. </exception>
		public CertificateID(DigestCalculator digestCalculator, X509CertificateHolder issuerCert, BigInteger number)
		{
			this.id = createCertID(digestCalculator, issuerCert, new ASN1Integer(number));
		}

		public virtual ASN1ObjectIdentifier getHashAlgOID()
		{
			return id.getHashAlgorithm().getAlgorithm();
		}

		public virtual byte[] getIssuerNameHash()
		{
			return id.getIssuerNameHash().getOctets();
		}

		public virtual byte[] getIssuerKeyHash()
		{
			return id.getIssuerKeyHash().getOctets();
		}

		/// <summary>
		/// return the serial number for the certificate associated
		/// with this request.
		/// </summary>
		public virtual BigInteger getSerialNumber()
		{
			return id.getSerialNumber().getValue();
		}

		public virtual bool matchesIssuer(X509CertificateHolder issuerCert, DigestCalculatorProvider digCalcProvider)
		{
			try
			{
				return createCertID(digCalcProvider.get(id.getHashAlgorithm()), issuerCert, id.getSerialNumber()).Equals(id);
			}
			catch (OperatorCreationException e)
			{
				throw new OCSPException("unable to create digest calculator: " + e.Message, e);
			}
		}

		public virtual CertID toASN1Primitive()
		{
			return id;
		}

		public override bool Equals(object o)
		{
			if (!(o is CertificateID))
			{
				return false;
			}

			CertificateID obj = (CertificateID)o;

			return id.toASN1Primitive().Equals(obj.id.toASN1Primitive());
		}

		public override int GetHashCode()
		{
			return id.toASN1Primitive().GetHashCode();
		}

		/// <summary>
		/// Create a new CertificateID for a new serial number derived from a previous one
		/// calculated for the same CA certificate.
		/// </summary>
		/// <param name="original"> the previously calculated CertificateID for the CA. </param>
		/// <param name="newSerialNumber"> the serial number for the new certificate of interest.
		/// </param>
		/// <returns> a new CertificateID for newSerialNumber </returns>
		public static CertificateID deriveCertificateID(CertificateID original, BigInteger newSerialNumber)
		{
			return new CertificateID(new CertID(original.id.getHashAlgorithm(), original.id.getIssuerNameHash(), original.id.getIssuerKeyHash(), new ASN1Integer(newSerialNumber)));
		}

		private static CertID createCertID(DigestCalculator digCalc, X509CertificateHolder issuerCert, ASN1Integer serialNumber)
		{
			try
			{
				OutputStream dgOut = digCalc.getOutputStream();

				dgOut.write(issuerCert.toASN1Structure().getSubject().getEncoded(ASN1Encoding_Fields.DER));
				dgOut.close();

				ASN1OctetString issuerNameHash = new DEROctetString(digCalc.getDigest());

				SubjectPublicKeyInfo info = issuerCert.getSubjectPublicKeyInfo();

				dgOut = digCalc.getOutputStream();

				dgOut.write(info.getPublicKeyData().getBytes());
				dgOut.close();

				ASN1OctetString issuerKeyHash = new DEROctetString(digCalc.getDigest());

				return new CertID(digCalc.getAlgorithmIdentifier(), issuerNameHash, issuerKeyHash, serialNumber);
			}
			catch (Exception e)
			{
				throw new OCSPException("problem creating ID: " + e, e);
			}
		}
	}

}