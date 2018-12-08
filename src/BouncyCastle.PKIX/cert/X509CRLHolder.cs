using System;

namespace org.bouncycastle.cert
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DEROutputStream = org.bouncycastle.asn1.DEROutputStream;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using CertificateList = org.bouncycastle.asn1.x509.CertificateList;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using IssuingDistributionPoint = org.bouncycastle.asn1.x509.IssuingDistributionPoint;
	using TBSCertList = org.bouncycastle.asn1.x509.TBSCertList;
	using ContentVerifier = org.bouncycastle.@operator.ContentVerifier;
	using ContentVerifierProvider = org.bouncycastle.@operator.ContentVerifierProvider;
	using Encodable = org.bouncycastle.util.Encodable;

	/// <summary>
	/// Holding class for an X.509 CRL structure.
	/// </summary>
	[Serializable]
	public class X509CRLHolder : Encodable
	{
		private const long serialVersionUID = 20170722001L;

		[NonSerialized]
		private CertificateList x509CRL;
		[NonSerialized]
		private bool isIndirect;
		[NonSerialized]
		private Extensions extensions;
		[NonSerialized]
		private GeneralNames issuerName;

		private static CertificateList parseStream(InputStream stream)
		{
			try
			{
				ASN1Primitive obj = (new ASN1InputStream(stream, true)).readObject();
				if (obj == null)
				{
					throw new IOException("no content found");
				}
				return CertificateList.getInstance(obj);
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

		private static bool isIndirectCRL(Extensions extensions)
		{
			if (extensions == null)
			{
				return false;
			}

			Extension ext = extensions.getExtension(Extension.issuingDistributionPoint);

			return ext != null && IssuingDistributionPoint.getInstance(ext.getParsedValue()).isIndirectCRL();
		}

		/// <summary>
		/// Create a X509CRLHolder from the passed in bytes.
		/// </summary>
		/// <param name="crlEncoding"> BER/DER encoding of the CRL </param>
		/// <exception cref="IOException"> in the event of corrupted data, or an incorrect structure. </exception>
		public X509CRLHolder(byte[] crlEncoding) : this(parseStream(new ByteArrayInputStream(crlEncoding)))
		{
		}

		/// <summary>
		/// Create a X509CRLHolder from the passed in InputStream.
		/// </summary>
		/// <param name="crlStream"> BER/DER encoded InputStream of the CRL </param>
		/// <exception cref="IOException"> in the event of corrupted data, or an incorrect structure. </exception>
		public X509CRLHolder(InputStream crlStream) : this(parseStream(crlStream))
		{
		}

		/// <summary>
		/// Create a X509CRLHolder from the passed in ASN.1 structure.
		/// </summary>
		/// <param name="x509CRL"> an ASN.1 CertificateList structure. </param>
		public X509CRLHolder(CertificateList x509CRL)
		{
			init(x509CRL);
		}

		private void init(CertificateList x509CRL)
		{
			this.x509CRL = x509CRL;
			this.extensions = x509CRL.getTBSCertList().getExtensions();
			this.isIndirect = isIndirectCRL(extensions);
			this.issuerName = new GeneralNames(new GeneralName(x509CRL.getIssuer()));
		}

		/// <summary>
		/// Return the ASN.1 encoding of this holder's CRL.
		/// </summary>
		/// <returns> a DER encoded byte array. </returns>
		/// <exception cref="IOException"> if an encoding cannot be generated. </exception>
		public virtual byte[] getEncoded()
		{
			return x509CRL.getEncoded();
		}

		/// <summary>
		/// Return the issuer of this holder's CRL.
		/// </summary>
		/// <returns> the CRL issuer. </returns>
		public virtual X500Name getIssuer()
		{
			return X500Name.getInstance(x509CRL.getIssuer());
		}

		public virtual X509CRLEntryHolder getRevokedCertificate(BigInteger serialNumber)
		{
			GeneralNames currentCA = issuerName;
			for (Enumeration en = x509CRL.getRevokedCertificateEnumeration(); en.hasMoreElements();)
			{
				TBSCertList.CRLEntry entry = (TBSCertList.CRLEntry)en.nextElement();

				if (entry.getUserCertificate().getValue().Equals(serialNumber))
				{
					return new X509CRLEntryHolder(entry, isIndirect, currentCA);
				}

				if (isIndirect && entry.hasExtensions())
				{
					Extension currentCaName = entry.getExtensions().getExtension(Extension.certificateIssuer);

					if (currentCaName != null)
					{
						currentCA = GeneralNames.getInstance(currentCaName.getParsedValue());
					}
				}
			}

			return null;
		}

		/// <summary>
		/// Return a collection of X509CRLEntryHolder objects, giving the details of the
		/// revoked certificates that appear on this CRL.
		/// </summary>
		/// <returns> the revoked certificates as a collection of X509CRLEntryHolder objects. </returns>
		public virtual Collection getRevokedCertificates()
		{
			TBSCertList.CRLEntry[] entries = x509CRL.getRevokedCertificates();
			List l = new ArrayList(entries.Length);
			GeneralNames currentCA = issuerName;

			for (Enumeration en = x509CRL.getRevokedCertificateEnumeration(); en.hasMoreElements();)
			{
				TBSCertList.CRLEntry entry = (TBSCertList.CRLEntry)en.nextElement();
				X509CRLEntryHolder crlEntry = new X509CRLEntryHolder(entry, isIndirect, currentCA);

				l.add(crlEntry);

				currentCA = crlEntry.getCertificateIssuer();
			}

			return l;
		}

		/// <summary>
		/// Return whether or not the holder's CRL contains extensions.
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
		/// Return the extensions block associated with this CRL if there is one.
		/// </summary>
		/// <returns> the extensions block, null otherwise. </returns>
		public virtual Extensions getExtensions()
		{
			return extensions;
		}

		/// <summary>
		/// Returns a list of ASN1ObjectIdentifier objects representing the OIDs of the
		/// extensions contained in this holder's CRL.
		/// </summary>
		/// <returns> a list of extension OIDs. </returns>
		public virtual List getExtensionOIDs()
		{
			return CertUtils.getExtensionOIDs(extensions);
		}

		/// <summary>
		/// Returns a set of ASN1ObjectIdentifier objects representing the OIDs of the
		/// critical extensions contained in this holder's CRL.
		/// </summary>
		/// <returns> a set of critical extension OIDs. </returns>
		public virtual Set getCriticalExtensionOIDs()
		{
			return CertUtils.getCriticalExtensionOIDs(extensions);
		}

		/// <summary>
		/// Returns a set of ASN1ObjectIdentifier objects representing the OIDs of the
		/// non-critical extensions contained in this holder's CRL.
		/// </summary>
		/// <returns> a set of non-critical extension OIDs. </returns>
		public virtual Set getNonCriticalExtensionOIDs()
		{
			return CertUtils.getNonCriticalExtensionOIDs(extensions);
		}

		/// <summary>
		/// Return the underlying ASN.1 structure for the CRL in this holder.
		/// </summary>
		/// <returns> a CertificateList object. </returns>
		public virtual CertificateList toASN1Structure()
		{
			return x509CRL;
		}

		/// <summary>
		/// Validate the signature on the CRL.
		/// </summary>
		/// <param name="verifierProvider"> a ContentVerifierProvider that can generate a verifier for the signature. </param>
		/// <returns> true if the signature is valid, false otherwise. </returns>
		/// <exception cref="CertException"> if the signature cannot be processed or is inappropriate. </exception>
		public virtual bool isSignatureValid(ContentVerifierProvider verifierProvider)
		{
			TBSCertList tbsCRL = x509CRL.getTBSCertList();

			if (!CertUtils.isAlgIdEqual(tbsCRL.getSignature(), x509CRL.getSignatureAlgorithm()))
			{
				throw new CertException("signature invalid - algorithm identifier mismatch");
			}

			ContentVerifier verifier;

			try
			{
				verifier = verifierProvider.get((tbsCRL.getSignature()));

				OutputStream sOut = verifier.getOutputStream();
				DEROutputStream dOut = new DEROutputStream(sOut);

				dOut.writeObject(tbsCRL);

				sOut.close();
			}
			catch (Exception e)
			{
				throw new CertException("unable to process signature: " + e.Message, e);
			}

			return verifier.verify(x509CRL.getSignature().getOctets());
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (!(o is X509CRLHolder))
			{
				return false;
			}

			X509CRLHolder other = (X509CRLHolder)o;

			return this.x509CRL.Equals(other.x509CRL);
		}

		public override int GetHashCode()
		{
			return this.x509CRL.GetHashCode();
		}

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			init(CertificateList.getInstance(@in.readObject()));
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(this.getEncoded());
		}
	}

}