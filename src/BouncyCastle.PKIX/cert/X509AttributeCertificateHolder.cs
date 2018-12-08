using System;

namespace org.bouncycastle.cert
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DEROutputStream = org.bouncycastle.asn1.DEROutputStream;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using AttCertValidityPeriod = org.bouncycastle.asn1.x509.AttCertValidityPeriod;
	using Attribute = org.bouncycastle.asn1.x509.Attribute;
	using AttributeCertificate = org.bouncycastle.asn1.x509.AttributeCertificate;
	using AttributeCertificateInfo = org.bouncycastle.asn1.x509.AttributeCertificateInfo;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using ContentVerifier = org.bouncycastle.@operator.ContentVerifier;
	using ContentVerifierProvider = org.bouncycastle.@operator.ContentVerifierProvider;
	using Encodable = org.bouncycastle.util.Encodable;

	/// <summary>
	/// Holding class for an X.509 AttributeCertificate structure.
	/// </summary>
	[Serializable]
	public class X509AttributeCertificateHolder : Encodable
	{
		private const long serialVersionUID = 20170722001L;

		private static Attribute[] EMPTY_ARRAY = new Attribute[0];

		[NonSerialized]
		private AttributeCertificate attrCert;
		[NonSerialized]
		private Extensions extensions;

		private static AttributeCertificate parseBytes(byte[] certEncoding)
		{
			try
			{
				return AttributeCertificate.getInstance(CertUtils.parseNonEmptyASN1(certEncoding));
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
		/// Create a X509AttributeCertificateHolder from the passed in bytes.
		/// </summary>
		/// <param name="certEncoding"> BER/DER encoding of the certificate. </param>
		/// <exception cref="IOException"> in the event of corrupted data, or an incorrect structure. </exception>
		public X509AttributeCertificateHolder(byte[] certEncoding) : this(parseBytes(certEncoding))
		{
		}

		/// <summary>
		/// Create a X509AttributeCertificateHolder from the passed in ASN.1 structure.
		/// </summary>
		/// <param name="attrCert"> an ASN.1 AttributeCertificate structure. </param>
		public X509AttributeCertificateHolder(AttributeCertificate attrCert)
		{
			init(attrCert);
		}

		private void init(AttributeCertificate attrCert)
		{
			this.attrCert = attrCert;
			this.extensions = attrCert.getAcinfo().getExtensions();
		}

		/// <summary>
		/// Return the ASN.1 encoding of this holder's attribute certificate.
		/// </summary>
		/// <returns> a DER encoded byte array. </returns>
		/// <exception cref="IOException"> if an encoding cannot be generated. </exception>
		public virtual byte[] getEncoded()
		{
			return attrCert.getEncoded();
		}

		public virtual int getVersion()
		{
			return attrCert.getAcinfo().getVersion().getValue().intValue() + 1;
		}

		/// <summary>
		/// Return the serial number of this attribute certificate.
		/// </summary>
		/// <returns> the serial number. </returns>
		public virtual BigInteger getSerialNumber()
		{
			return attrCert.getAcinfo().getSerialNumber().getValue();
		}

		/// <summary>
		/// Return the holder details for this attribute certificate.
		/// </summary>
		/// <returns> this attribute certificate's holder structure. </returns>
		public virtual AttributeCertificateHolder getHolder()
		{
			return new AttributeCertificateHolder((ASN1Sequence)attrCert.getAcinfo().getHolder().toASN1Primitive());
		}

		/// <summary>
		/// Return the issuer details for this attribute certificate.
		/// </summary>
		/// <returns> this attribute certificate's issuer structure, </returns>
		public virtual AttributeCertificateIssuer getIssuer()
		{
			return new AttributeCertificateIssuer(attrCert.getAcinfo().getIssuer());
		}

		/// <summary>
		/// Return the date before which this attribute certificate is not valid.
		/// </summary>
		/// <returns> the start date for the attribute certificate's validity period. </returns>
		public virtual DateTime getNotBefore()
		{
			return CertUtils.recoverDate(attrCert.getAcinfo().getAttrCertValidityPeriod().getNotBeforeTime());
		}

		/// <summary>
		/// Return the date after which this attribute certificate is not valid.
		/// </summary>
		/// <returns> the final date for the attribute certificate's validity period. </returns>
		public virtual DateTime getNotAfter()
		{
			return CertUtils.recoverDate(attrCert.getAcinfo().getAttrCertValidityPeriod().getNotAfterTime());
		}

		/// <summary>
		/// Return the attributes, if any associated with this request.
		/// </summary>
		/// <returns> an array of Attribute, zero length if none present. </returns>
		public virtual Attribute[] getAttributes()
		{
			ASN1Sequence seq = attrCert.getAcinfo().getAttributes();
			Attribute[] attrs = new Attribute[seq.size()];

			for (int i = 0; i != seq.size(); i++)
			{
				attrs[i] = Attribute.getInstance(seq.getObjectAt(i));
			}

			return attrs;
		}

		/// <summary>
		/// Return an  array of attributes matching the passed in type OID.
		/// </summary>
		/// <param name="type"> the type of the attribute being looked for. </param>
		/// <returns> an array of Attribute of the requested type, zero length if none present. </returns>
		public virtual Attribute[] getAttributes(ASN1ObjectIdentifier type)
		{
			ASN1Sequence seq = attrCert.getAcinfo().getAttributes();
			List list = new ArrayList();

			for (int i = 0; i != seq.size(); i++)
			{
				Attribute attr = Attribute.getInstance(seq.getObjectAt(i));
				if (attr.getAttrType().Equals(type))
				{
					list.add(attr);
				}
			}

			if (list.size() == 0)
			{
				return EMPTY_ARRAY;
			}

			return (Attribute[])list.toArray(new Attribute[list.size()]);
		}

		/// <summary>
		/// Return whether or not the holder's attribute certificate contains extensions.
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
		/// extensions contained in this holder's attribute certificate.
		/// </summary>
		/// <returns> a list of extension OIDs. </returns>
		public virtual List getExtensionOIDs()
		{
			return CertUtils.getExtensionOIDs(extensions);
		}

		/// <summary>
		/// Returns a set of ASN1ObjectIdentifier objects representing the OIDs of the
		/// critical extensions contained in this holder's attribute certificate.
		/// </summary>
		/// <returns> a set of critical extension OIDs. </returns>
		public virtual Set getCriticalExtensionOIDs()
		{
			return CertUtils.getCriticalExtensionOIDs(extensions);
		}

		/// <summary>
		/// Returns a set of ASN1ObjectIdentifier objects representing the OIDs of the
		/// non-critical extensions contained in this holder's attribute certificate.
		/// </summary>
		/// <returns> a set of non-critical extension OIDs. </returns>
		public virtual Set getNonCriticalExtensionOIDs()
		{
			return CertUtils.getNonCriticalExtensionOIDs(extensions);
		}

		public virtual bool[] getIssuerUniqueID()
		{
			return CertUtils.bitStringToBoolean(attrCert.getAcinfo().getIssuerUniqueID());
		}

		/// <summary>
		/// Return the details of the signature algorithm used to create this attribute certificate.
		/// </summary>
		/// <returns> the AlgorithmIdentifier describing the signature algorithm used to create this attribute certificate. </returns>
		public virtual AlgorithmIdentifier getSignatureAlgorithm()
		{
			return attrCert.getSignatureAlgorithm();
		}

		/// <summary>
		/// Return the bytes making up the signature associated with this attribute certificate.
		/// </summary>
		/// <returns> the attribute certificate signature bytes. </returns>
		public virtual byte[] getSignature()
		{
			return attrCert.getSignatureValue().getOctets();
		}

		/// <summary>
		/// Return the underlying ASN.1 structure for the attribute certificate in this holder.
		/// </summary>
		/// <returns> a AttributeCertificate object. </returns>
		public virtual AttributeCertificate toASN1Structure()
		{
			return attrCert;
		}

		/// <summary>
		/// Return whether or not this attribute certificate is valid on a particular date.
		/// </summary>
		/// <param name="date"> the date of interest. </param>
		/// <returns> true if the attribute certificate is valid, false otherwise. </returns>
		public virtual bool isValidOn(DateTime date)
		{
			AttCertValidityPeriod certValidityPeriod = attrCert.getAcinfo().getAttrCertValidityPeriod();

			return !date < CertUtils.recoverDate(certValidityPeriod.getNotBeforeTime()) && !date > CertUtils.recoverDate(certValidityPeriod.getNotAfterTime());
		}

		/// <summary>
		/// Validate the signature on the attribute certificate in this holder.
		/// </summary>
		/// <param name="verifierProvider"> a ContentVerifierProvider that can generate a verifier for the signature. </param>
		/// <returns> true if the signature is valid, false otherwise. </returns>
		/// <exception cref="CertException"> if the signature cannot be processed or is inappropriate. </exception>
		public virtual bool isSignatureValid(ContentVerifierProvider verifierProvider)
		{
			AttributeCertificateInfo acinfo = attrCert.getAcinfo();

			if (!CertUtils.isAlgIdEqual(acinfo.getSignature(), attrCert.getSignatureAlgorithm()))
			{
				throw new CertException("signature invalid - algorithm identifier mismatch");
			}

			ContentVerifier verifier;

			try
			{
				verifier = verifierProvider.get((acinfo.getSignature()));

				OutputStream sOut = verifier.getOutputStream();
				DEROutputStream dOut = new DEROutputStream(sOut);

				dOut.writeObject(acinfo);

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

			if (!(o is X509AttributeCertificateHolder))
			{
				return false;
			}

			X509AttributeCertificateHolder other = (X509AttributeCertificateHolder)o;

			return this.attrCert.Equals(other.attrCert);
		}

		public override int GetHashCode()
		{
			return this.attrCert.GetHashCode();
		}

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			init(AttributeCertificate.getInstance(@in.readObject()));
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(this.getEncoded());
		}
	}

}