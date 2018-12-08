using System;

namespace org.bouncycastle.cert
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DEROutputStream = org.bouncycastle.asn1.DEROutputStream;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using TBSCertificate = org.bouncycastle.asn1.x509.TBSCertificate;
	using ContentVerifier = org.bouncycastle.@operator.ContentVerifier;
	using ContentVerifierProvider = org.bouncycastle.@operator.ContentVerifierProvider;
	using Encodable = org.bouncycastle.util.Encodable;

	/// <summary>
	/// Holding class for an X.509 Certificate structure.
	/// </summary>
	[Serializable]
	public class X509CertificateHolder : Encodable
	{
		private const long serialVersionUID = 20170722001L;

		[NonSerialized]
		private Certificate x509Certificate;
		[NonSerialized]
		private Extensions extensions;

		private static Certificate parseBytes(byte[] certEncoding)
		{
			try
			{
				return Certificate.getInstance(CertUtils.parseNonEmptyASN1(certEncoding));
			}
			catch (ClassCastException e)
			{
				throw new CertIOException("malformed data: " + e.getMessage(), e);
			}
			catch (IllegalArgumentException e)
			{
				throw new CertIOException("malformed data: " + e.getMessage(), e);
			}
		}

		/// <summary>
		/// Create a X509CertificateHolder from the passed in bytes.
		/// </summary>
		/// <param name="certEncoding"> BER/DER encoding of the certificate. </param>
		/// <exception cref="IOException"> in the event of corrupted data, or an incorrect structure. </exception>
		public X509CertificateHolder(byte[] certEncoding) : this(parseBytes(certEncoding))
		{
		}

		/// <summary>
		/// Create a X509CertificateHolder from the passed in ASN.1 structure.
		/// </summary>
		/// <param name="x509Certificate"> an ASN.1 Certificate structure. </param>
		public X509CertificateHolder(Certificate x509Certificate)
		{
			init(x509Certificate);
		}

		private void init(Certificate x509Certificate)
		{
			this.x509Certificate = x509Certificate;
			this.extensions = x509Certificate.getTBSCertificate().getExtensions();
		}

		public virtual int getVersionNumber()
		{
			return x509Certificate.getVersionNumber();
		}

		/// @deprecated use getVersionNumber 
		public virtual int getVersion()
		{
			return x509Certificate.getVersionNumber();
		}

		/// <summary>
		/// Return whether or not the holder's certificate contains extensions.
		/// </summary>
		/// <returns> true if extension are present, false otherwise. </returns>
		public virtual bool hasExtensions()
		{
			return extensions != null;
		}

		/// <summary>
		/// Look up the extension associated with the passed in OID.
		/// </summary>
		/// <param name="oid"> the OID of the extension of interest.
		/// </param>
		/// <returns> the extension if present, null otherwise. </returns>
		public virtual Extension getExtension(ASN1ObjectIdentifier oid)
		{
			if (extensions != null)
			{
				return extensions.getExtension(oid);
			}

			return null;
		}

		/// <summary>
		/// Return the extensions block associated with this certificate if there is one.
		/// </summary>
		/// <returns> the extensions block, null otherwise. </returns>
		public virtual Extensions getExtensions()
		{
			return extensions;
		}

		/// <summary>
		/// Returns a list of ASN1ObjectIdentifier objects representing the OIDs of the
		/// extensions contained in this holder's certificate.
		/// </summary>
		/// <returns> a list of extension OIDs. </returns>
		public virtual List getExtensionOIDs()
		{
			return CertUtils.getExtensionOIDs(extensions);
		}

		/// <summary>
		/// Returns a set of ASN1ObjectIdentifier objects representing the OIDs of the
		/// critical extensions contained in this holder's certificate.
		/// </summary>
		/// <returns> a set of critical extension OIDs. </returns>
		public virtual Set getCriticalExtensionOIDs()
		{
			return CertUtils.getCriticalExtensionOIDs(extensions);
		}

		/// <summary>
		/// Returns a set of ASN1ObjectIdentifier objects representing the OIDs of the
		/// non-critical extensions contained in this holder's certificate.
		/// </summary>
		/// <returns> a set of non-critical extension OIDs. </returns>
		public virtual Set getNonCriticalExtensionOIDs()
		{
			return CertUtils.getNonCriticalExtensionOIDs(extensions);
		}

		/// <summary>
		/// Return the serial number of this attribute certificate.
		/// </summary>
		/// <returns> the serial number. </returns>
		public virtual BigInteger getSerialNumber()
		{
			return x509Certificate.getSerialNumber().getValue();
		}

		/// <summary>
		/// Return the issuer of this certificate.
		/// </summary>
		/// <returns> the certificate issuer. </returns>
		public virtual X500Name getIssuer()
		{
			return X500Name.getInstance(x509Certificate.getIssuer());
		}

		/// <summary>
		/// Return the subject this certificate is for.
		/// </summary>
		/// <returns> the subject for the certificate. </returns>
		public virtual X500Name getSubject()
		{
			return X500Name.getInstance(x509Certificate.getSubject());
		}

		/// <summary>
		/// Return the date before which this certificate is not valid.
		/// </summary>
		/// <returns> the start time for the certificate's validity period. </returns>
		public virtual DateTime getNotBefore()
		{
			return x509Certificate.getStartDate().getDate();
		}

		/// <summary>
		/// Return the date after which this certificate is not valid.
		/// </summary>
		/// <returns> the final time for the certificate's validity period. </returns>
		public virtual DateTime getNotAfter()
		{
			return x509Certificate.getEndDate().getDate();
		}

		/// <summary>
		/// Return the SubjectPublicKeyInfo describing the public key this certificate is carrying.
		/// </summary>
		/// <returns> the public key ASN.1 structure contained in the certificate. </returns>
		public virtual SubjectPublicKeyInfo getSubjectPublicKeyInfo()
		{
			return x509Certificate.getSubjectPublicKeyInfo();
		}

		/// <summary>
		/// Return the underlying ASN.1 structure for the certificate in this holder.
		/// </summary>
		/// <returns> a Certificate object. </returns>
		public virtual Certificate toASN1Structure()
		{
			return x509Certificate;
		}

		/// <summary>
		/// Return the details of the signature algorithm used to create this attribute certificate.
		/// </summary>
		/// <returns> the AlgorithmIdentifier describing the signature algorithm used to create this attribute certificate. </returns>
		public virtual AlgorithmIdentifier getSignatureAlgorithm()
		{
			return x509Certificate.getSignatureAlgorithm();
		}

		/// <summary>
		/// Return the bytes making up the signature associated with this attribute certificate.
		/// </summary>
		/// <returns> the attribute certificate signature bytes. </returns>
		public virtual byte[] getSignature()
		{
			return x509Certificate.getSignature().getOctets();
		}

		/// <summary>
		/// Return whether or not this certificate is valid on a particular date.
		/// </summary>
		/// <param name="date"> the date of interest. </param>
		/// <returns> true if the certificate is valid, false otherwise. </returns>
		public virtual bool isValidOn(DateTime date)
		{
			return !date < x509Certificate.getStartDate().getDate() && !date > x509Certificate.getEndDate().getDate();
		}

		/// <summary>
		/// Validate the signature on the certificate in this holder.
		/// </summary>
		/// <param name="verifierProvider"> a ContentVerifierProvider that can generate a verifier for the signature. </param>
		/// <returns> true if the signature is valid, false otherwise. </returns>
		/// <exception cref="CertException"> if the signature cannot be processed or is inappropriate. </exception>
		public virtual bool isSignatureValid(ContentVerifierProvider verifierProvider)
		{
			TBSCertificate tbsCert = x509Certificate.getTBSCertificate();

			if (!CertUtils.isAlgIdEqual(tbsCert.getSignature(), x509Certificate.getSignatureAlgorithm()))
			{
				throw new CertException("signature invalid - algorithm identifier mismatch");
			}

			ContentVerifier verifier;

			try
			{
				verifier = verifierProvider.get((tbsCert.getSignature()));

				OutputStream sOut = verifier.getOutputStream();
				DEROutputStream dOut = new DEROutputStream(sOut);

				dOut.writeObject(tbsCert);

				sOut.close();
			}
			catch (Exception e)
			{
				throw new CertException("unable to process signature: " + e.Message, e);
			}

			return verifier.verify(this.getSignature());
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (!(o is X509CertificateHolder))
			{
				return false;
			}

			X509CertificateHolder other = (X509CertificateHolder)o;

			return this.x509Certificate.Equals(other.x509Certificate);
		}

		public override int GetHashCode()
		{
			return this.x509Certificate.GetHashCode();
		}

		/// <summary>
		/// Return the ASN.1 encoding of this holder's certificate.
		/// </summary>
		/// <returns> a DER encoded byte array. </returns>
		/// <exception cref="IOException"> if an encoding cannot be generated. </exception>
		public virtual byte[] getEncoded()
		{
			return x509Certificate.getEncoded();
		}

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			init(Certificate.getInstance(@in.readObject()));
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(this.getEncoded());
		}
	}

}