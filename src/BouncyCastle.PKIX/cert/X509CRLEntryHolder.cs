using System;

namespace org.bouncycastle.cert
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using TBSCertList = org.bouncycastle.asn1.x509.TBSCertList;

	/// <summary>
	/// Holding class for an X.509 CRL Entry structure.
	/// </summary>
	public class X509CRLEntryHolder
	{
		private TBSCertList.CRLEntry entry;
		private GeneralNames ca;

		public X509CRLEntryHolder(TBSCertList.CRLEntry entry, bool isIndirect, GeneralNames previousCA)
		{
			this.entry = entry;
			this.ca = previousCA;

			if (isIndirect && entry.hasExtensions())
			{
				Extension currentCaName = entry.getExtensions().getExtension(Extension.certificateIssuer);

				if (currentCaName != null)
				{
					ca = GeneralNames.getInstance(currentCaName.getParsedValue());
				}
			}
		}

		/// <summary>
		/// Return the serial number of the certificate associated with this CRLEntry.
		/// </summary>
		/// <returns> the revoked certificate's serial number. </returns>
		public virtual BigInteger getSerialNumber()
		{
			return entry.getUserCertificate().getValue();
		}

		/// <summary>
		/// Return the date on which the certificate associated with this CRLEntry was revoked.
		/// </summary>
		/// <returns> the revocation date for the revoked certificate. </returns>
		public virtual DateTime getRevocationDate()
		{
			return entry.getRevocationDate().getDate();
		}

		/// <summary>
		/// Return whether or not the holder's CRL entry contains extensions.
		/// </summary>
		/// <returns> true if extension are present, false otherwise. </returns>
		public virtual bool hasExtensions()
		{
			return entry.hasExtensions();
		}

		/// <summary>
		/// Return the available names for the certificate issuer for the certificate referred to by this CRL entry.
		/// <para>
		/// Note: this will be the issuer of the CRL unless it has been specified that the CRL is indirect
		/// in the IssuingDistributionPoint extension and either a previous entry, or the current one,
		/// has specified a different CA via the certificateIssuer extension.
		/// </para>
		/// </summary>
		/// <returns> the revoked certificate's issuer. </returns>
		public virtual GeneralNames getCertificateIssuer()
		{
			return this.ca;
		}

		/// <summary>
		/// Look up the extension associated with the passed in OID.
		/// </summary>
		/// <param name="oid"> the OID of the extension of interest.
		/// </param>
		/// <returns> the extension if present, null otherwise. </returns>
		public virtual Extension getExtension(ASN1ObjectIdentifier oid)
		{
			Extensions extensions = entry.getExtensions();

			if (extensions != null)
			{
				return extensions.getExtension(oid);
			}

			return null;
		}

		/// <summary>
		/// Return the extensions block associated with this CRL entry if there is one.
		/// </summary>
		/// <returns> the extensions block, null otherwise. </returns>
		public virtual Extensions getExtensions()
		{
			return entry.getExtensions();
		}

		/// <summary>
		/// Returns a list of ASN1ObjectIdentifier objects representing the OIDs of the
		/// extensions contained in this holder's CRL entry.
		/// </summary>
		/// <returns> a list of extension OIDs. </returns>
		public virtual List getExtensionOIDs()
		{
			return CertUtils.getExtensionOIDs(entry.getExtensions());
		}

		/// <summary>
		/// Returns a set of ASN1ObjectIdentifier objects representing the OIDs of the
		/// critical extensions contained in this holder's CRL entry.
		/// </summary>
		/// <returns> a set of critical extension OIDs. </returns>
		public virtual Set getCriticalExtensionOIDs()
		{
			return CertUtils.getCriticalExtensionOIDs(entry.getExtensions());
		}

		/// <summary>
		/// Returns a set of ASN1ObjectIdentifier objects representing the OIDs of the
		/// non-critical extensions contained in this holder's CRL entry.
		/// </summary>
		/// <returns> a set of non-critical extension OIDs. </returns>
		public virtual Set getNonCriticalExtensionOIDs()
		{
			return CertUtils.getNonCriticalExtensionOIDs(entry.getExtensions());
		}
	}

}