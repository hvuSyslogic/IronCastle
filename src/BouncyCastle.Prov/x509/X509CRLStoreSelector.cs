using System;

namespace org.bouncycastle.x509
{

	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Arrays = org.bouncycastle.util.Arrays;
	using Selector = org.bouncycastle.util.Selector;
	using X509ExtensionUtil = org.bouncycastle.x509.extension.X509ExtensionUtil;

	/// <summary>
	/// This class is a Selector implementation for X.509 certificate revocation
	/// lists.
	/// </summary>
	/// <seealso cref= org.bouncycastle.util.Selector </seealso>
	/// <seealso cref= org.bouncycastle.x509.X509Store </seealso>
	/// <seealso cref= org.bouncycastle.jce.provider.X509StoreCRLCollection </seealso>
	public class X509CRLStoreSelector : X509CRLSelector, Selector
	{
		private bool deltaCRLIndicator = false;

		private bool completeCRLEnabled = false;

		private BigInteger maxBaseCRLNumber = null;

		private byte[] issuingDistributionPoint = null;

		private bool issuingDistributionPointEnabled = false;

		private X509AttributeCertificate attrCertChecking;

		/// <summary>
		/// Returns if the issuing distribution point criteria should be applied.
		/// Defaults to <code>false</code>.
		/// <para>
		/// You may also set the issuing distribution point criteria if not a missing
		/// issuing distribution point should be assumed.
		/// 
		/// </para>
		/// </summary>
		/// <returns> Returns if the issuing distribution point check is enabled. </returns>
		public virtual bool isIssuingDistributionPointEnabled()
		{
			return issuingDistributionPointEnabled;
		}

		/// <summary>
		/// Enables or disables the issuing distribution point check.
		/// </summary>
		/// <param name="issuingDistributionPointEnabled"> <code>true</code> to enable the
		///            issuing distribution point check. </param>
		public virtual void setIssuingDistributionPointEnabled(bool issuingDistributionPointEnabled)
		{
			this.issuingDistributionPointEnabled = issuingDistributionPointEnabled;
		}

		/// <summary>
		/// Sets the attribute certificate being checked. This is not a criterion.
		/// Rather, it is optional information that may help a <seealso cref="X509Store"/> find
		/// CRLs that would be relevant when checking revocation for the specified
		/// attribute certificate. If <code>null</code> is specified, then no such
		/// optional information is provided.
		/// </summary>
		/// <param name="attrCert"> the <code>X509AttributeCertificate</code> being checked (or
		///            <code>null</code>) </param>
		/// <seealso cref= #getAttrCertificateChecking() </seealso>
		public virtual void setAttrCertificateChecking(X509AttributeCertificate attrCert)
		{
			attrCertChecking = attrCert;
		}

		/// <summary>
		/// Returns the attribute certificate being checked.
		/// </summary>
		/// <returns> Returns the attribute certificate being checked. </returns>
		/// <seealso cref= #setAttrCertificateChecking(X509AttributeCertificate) </seealso>
		public virtual X509AttributeCertificate getAttrCertificateChecking()
		{
			return attrCertChecking;
		}

		public virtual bool match(object obj)
		{
			if (!(obj is X509CRL))
			{
				return false;
			}
			X509CRL crl = (X509CRL)obj;
			ASN1Integer dci = null;
			try
			{
				byte[] bytes = crl.getExtensionValue(Extension.deltaCRLIndicator.getId());
				if (bytes != null)
				{
					dci = ASN1Integer.getInstance(X509ExtensionUtil.fromExtensionValue(bytes));
				}
			}
			catch (Exception)
			{
				return false;
			}
			if (isDeltaCRLIndicatorEnabled())
			{
				if (dci == null)
				{
					return false;
				}
			}
			if (isCompleteCRLEnabled())
			{
				if (dci != null)
				{
					return false;
				}
			}
			if (dci != null)
			{

				if (maxBaseCRLNumber != null)
				{
					if (dci.getPositiveValue().compareTo(maxBaseCRLNumber) == 1)
					{
						return false;
					}
				}
			}
			if (issuingDistributionPointEnabled)
			{
				byte[] idp = crl.getExtensionValue(Extension.issuingDistributionPoint.getId());
				if (issuingDistributionPoint == null)
				{
					if (idp != null)
					{
						return false;
					}
				}
				else
				{
					if (!Arrays.areEqual(idp, issuingDistributionPoint))
					{
						return false;
					}
				}

			}
			return base.match((X509CRL)obj);
		}

		public virtual bool match(CRL crl)
		{
			return match((object)crl);
		}

		/// <summary>
		/// Returns if this selector must match CRLs with the delta CRL indicator
		/// extension set. Defaults to <code>false</code>.
		/// </summary>
		/// <returns> Returns <code>true</code> if only CRLs with the delta CRL
		///         indicator extension are selected. </returns>
		public virtual bool isDeltaCRLIndicatorEnabled()
		{
			return deltaCRLIndicator;
		}

		/// <summary>
		/// If this is set to <code>true</code> the CRL reported contains the delta
		/// CRL indicator CRL extension.
		/// <para>
		/// <seealso cref="#setCompleteCRLEnabled(boolean)"/> and
		/// <seealso cref="#setDeltaCRLIndicatorEnabled(boolean)"/> excluded each other.
		/// 
		/// </para>
		/// </summary>
		/// <param name="deltaCRLIndicator"> <code>true</code> if the delta CRL indicator
		///            extension must be in the CRL. </param>
		public virtual void setDeltaCRLIndicatorEnabled(bool deltaCRLIndicator)
		{
			this.deltaCRLIndicator = deltaCRLIndicator;
		}

		/// <summary>
		/// Returns an instance of this from a <code>X509CRLSelector</code>.
		/// </summary>
		/// <param name="selector"> A <code>X509CRLSelector</code> instance. </param>
		/// <returns> An instance of an <code>X509CRLStoreSelector</code>. </returns>
		/// <exception cref="IllegalArgumentException"> if selector is null or creation
		///                fails. </exception>
		public static X509CRLStoreSelector getInstance(X509CRLSelector selector)
		{
			if (selector == null)
			{
				throw new IllegalArgumentException("cannot create from null selector");
			}
			X509CRLStoreSelector cs = new X509CRLStoreSelector();
			cs.setCertificateChecking(selector.getCertificateChecking());
			cs.setDateAndTime(selector.getDateAndTime());
			try
			{
				cs.setIssuerNames(selector.getIssuerNames());
			}
			catch (IOException e)
			{
				// cannot happen
				throw new IllegalArgumentException(e.Message);
			}
			cs.setIssuers(selector.getIssuers());
			cs.setMaxCRLNumber(selector.getMaxCRL());
			cs.setMinCRLNumber(selector.getMinCRL());
			return cs;
		}

		public virtual object clone()
		{
			X509CRLStoreSelector sel = X509CRLStoreSelector.getInstance(this);
			sel.deltaCRLIndicator = deltaCRLIndicator;
			sel.completeCRLEnabled = completeCRLEnabled;
			sel.maxBaseCRLNumber = maxBaseCRLNumber;
			sel.attrCertChecking = attrCertChecking;
			sel.issuingDistributionPointEnabled = issuingDistributionPointEnabled;
			sel.issuingDistributionPoint = Arrays.clone(issuingDistributionPoint);
			return sel;
		}

		/// <summary>
		/// If <code>true</code> only complete CRLs are returned. Defaults to
		/// <code>false</code>.
		/// </summary>
		/// <returns> <code>true</code> if only complete CRLs are returned. </returns>
		public virtual bool isCompleteCRLEnabled()
		{
			return completeCRLEnabled;
		}

		/// <summary>
		/// If set to <code>true</code> only complete CRLs are returned.
		/// <para>
		/// <seealso cref="#setCompleteCRLEnabled(boolean)"/> and
		/// <seealso cref="#setDeltaCRLIndicatorEnabled(boolean)"/> excluded each other.
		/// 
		/// </para>
		/// </summary>
		/// <param name="completeCRLEnabled"> <code>true</code> if only complete CRLs
		///            should be returned. </param>
		public virtual void setCompleteCRLEnabled(bool completeCRLEnabled)
		{
			this.completeCRLEnabled = completeCRLEnabled;
		}

		/// <summary>
		/// Get the maximum base CRL number. Defaults to <code>null</code>.
		/// </summary>
		/// <returns> Returns the maximum base CRL number. </returns>
		/// <seealso cref= #setMaxBaseCRLNumber(BigInteger) </seealso>
		public virtual BigInteger getMaxBaseCRLNumber()
		{
			return maxBaseCRLNumber;
		}

		/// <summary>
		/// Sets the maximum base CRL number. Setting to <code>null</code> disables
		/// this cheack.
		/// <para>
		/// This is only meaningful for delta CRLs. Complete CRLs must have a CRL
		/// number which is greater or equal than the base number of the
		/// corresponding CRL.
		/// 
		/// </para>
		/// </summary>
		/// <param name="maxBaseCRLNumber"> The maximum base CRL number to set. </param>
		public virtual void setMaxBaseCRLNumber(BigInteger maxBaseCRLNumber)
		{
			this.maxBaseCRLNumber = maxBaseCRLNumber;
		}

		/// <summary>
		/// Returns the issuing distribution point. Defaults to <code>null</code>,
		/// which is a missing issuing distribution point extension.
		/// <para>
		/// The internal byte array is cloned before it is returned.
		/// </para>
		/// <para>
		/// The criteria must be enable with
		/// <seealso cref="#setIssuingDistributionPointEnabled(boolean)"/>.
		/// 
		/// </para>
		/// </summary>
		/// <returns> Returns the issuing distribution point. </returns>
		/// <seealso cref= #setIssuingDistributionPoint(byte[]) </seealso>
		public virtual byte[] getIssuingDistributionPoint()
		{
			return Arrays.clone(issuingDistributionPoint);
		}

		/// <summary>
		/// Sets the issuing distribution point.
		/// <para>
		/// The issuing distribution point extension is a CRL extension which
		/// identifies the scope and the distribution point of a CRL. The scope
		/// contains among others information about revocation reasons contained in
		/// the CRL. Delta CRLs and complete CRLs must have matching issuing
		/// distribution points.
		/// </para>
		/// <para>
		/// The byte array is cloned to protect against subsequent modifications.
		/// </para>
		/// <para>
		/// You must also enable or disable this criteria with
		/// <seealso cref="#setIssuingDistributionPointEnabled(boolean)"/>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="issuingDistributionPoint"> The issuing distribution point to set.
		///            This is the DER encoded OCTET STRING extension value. </param>
		/// <seealso cref= #getIssuingDistributionPoint() </seealso>
		public virtual void setIssuingDistributionPoint(byte[] issuingDistributionPoint)
		{
			this.issuingDistributionPoint = Arrays.clone(issuingDistributionPoint);
		}
	}

}