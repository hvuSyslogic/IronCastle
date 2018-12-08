using System;

namespace org.bouncycastle.jcajce
{

	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Arrays = org.bouncycastle.util.Arrays;
	using Selector = org.bouncycastle.util.Selector;

	/// <summary>
	/// This class is a Selector implementation for X.509 certificate revocation
	/// lists.
	/// </summary>
	/// <seealso cref= org.bouncycastle.util.Selector </seealso>
	public class PKIXCRLStoreSelector<T> : Selector<T> where T : java.security.cert.CRL
	{
		/// <summary>
		/// Builder for a PKIXCRLStoreSelector.
		/// </summary>
		public class Builder
		{
			internal readonly CRLSelector baseSelector;

			internal bool deltaCRLIndicator = false;
			internal bool completeCRLEnabled = false;
			internal BigInteger maxBaseCRLNumber = null;
			internal byte[] issuingDistributionPoint = null;
			internal bool issuingDistributionPointEnabled = false;

			/// <summary>
			/// Constructor initializing a builder with a CertSelector.
			/// </summary>
			/// <param name="crlSelector"> the CertSelector to copy the match details from. </param>
			public Builder(CRLSelector crlSelector)
			{
				this.baseSelector = (CRLSelector)crlSelector.clone();
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
			public virtual Builder setCompleteCRLEnabled(bool completeCRLEnabled)
			{
				this.completeCRLEnabled = completeCRLEnabled;

				return this;
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
			public virtual Builder setDeltaCRLIndicatorEnabled(bool deltaCRLIndicator)
			{
				this.deltaCRLIndicator = deltaCRLIndicator;

				return this;
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
			/// Enables or disables the issuing distribution point check.
			/// </summary>
			/// <param name="issuingDistributionPointEnabled"> <code>true</code> to enable the
			///            issuing distribution point check. </param>
			public virtual void setIssuingDistributionPointEnabled(bool issuingDistributionPointEnabled)
			{
				this.issuingDistributionPointEnabled = issuingDistributionPointEnabled;
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

			/// <summary>
			/// Build a selector.
			/// </summary>
			/// <returns> a new PKIXCRLStoreSelector </returns>
//JAVA TO C# CONVERTER WARNING: Java wildcard generics have no direct equivalent in .NET:
//ORIGINAL LINE: public PKIXCRLStoreSelector<? extends java.security.cert.CRL> build()
			public virtual PKIXCRLStoreSelector<CRL> build()
			{
				return new PKIXCRLStoreSelector(this);
			}
		}

		private readonly CRLSelector baseSelector;
		private readonly bool deltaCRLIndicator;
		private readonly bool completeCRLEnabled;
		private readonly BigInteger maxBaseCRLNumber;
		private readonly byte[] issuingDistributionPoint;
		private readonly bool issuingDistributionPointEnabled;

		private PKIXCRLStoreSelector(Builder baseBuilder)
		{
			this.baseSelector = baseBuilder.baseSelector;
			this.deltaCRLIndicator = baseBuilder.deltaCRLIndicator;
			this.completeCRLEnabled = baseBuilder.completeCRLEnabled;
			this.maxBaseCRLNumber = baseBuilder.maxBaseCRLNumber;
			this.issuingDistributionPoint = baseBuilder.issuingDistributionPoint;
			this.issuingDistributionPointEnabled = baseBuilder.issuingDistributionPointEnabled;
		}


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



		public virtual bool match(CRL obj)
		{
			if (!(obj is X509CRL))
			{
				return baseSelector.match(obj);
			}

			X509CRL crl = (X509CRL)obj;
			ASN1Integer dci = null;
			try
			{
				byte[] bytes = crl.getExtensionValue(Extension.deltaCRLIndicator.getId());
				if (bytes != null)
				{
					dci = ASN1Integer.getInstance(ASN1OctetString.getInstance(bytes).getOctets());
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
			return baseSelector.match(obj);
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

		public virtual object clone()
		{
			return this;
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
		/// Get the maximum base CRL number. Defaults to <code>null</code>.
		/// </summary>
		/// <returns> Returns the maximum base CRL number. </returns>
		public virtual BigInteger getMaxBaseCRLNumber()
		{
			return maxBaseCRLNumber;
		}


		/// <summary>
		/// Returns the issuing distribution point. Defaults to <code>null</code>,
		/// which is a missing issuing distribution point extension.
		/// <para>
		/// The internal byte array is cloned before it is returned.
		/// </para>
		/// <para>
		/// The criteria must be enable with Builder.setIssuingDistributionPointEnabled(boolean)}.
		/// 
		/// </para>
		/// </summary>
		/// <returns> Returns the issuing distribution point. </returns>
		public virtual byte[] getIssuingDistributionPoint()
		{
			return Arrays.clone(issuingDistributionPoint);
		}

		public virtual X509Certificate getCertificateChecking()
		{
			if (baseSelector is X509CRLSelector)
			{
				return ((X509CRLSelector)baseSelector).getCertificateChecking();
			}

			return null;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public static java.util.Collection<? extends java.security.cert.CRL> getCRLs(final PKIXCRLStoreSelector selector, java.security.cert.CertStore certStore) throws java.security.cert.CertStoreException
//JAVA TO C# CONVERTER WARNING: Java wildcard generics have no direct equivalent in .NET:
		public static Collection<CRL> getCRLs(PKIXCRLStoreSelector selector, CertStore certStore)
		{
			return certStore.getCRLs(new SelectorClone(selector));
		}

		public class SelectorClone : X509CRLSelector
		{
			internal readonly PKIXCRLStoreSelector selector;

			public SelectorClone(PKIXCRLStoreSelector selector)
			{
				this.selector = selector;

				if (selector.baseSelector is X509CRLSelector)
				{
					X509CRLSelector baseSelector = (X509CRLSelector)selector.baseSelector;

					this.setCertificateChecking(baseSelector.getCertificateChecking());
					this.setDateAndTime(baseSelector.getDateAndTime());
					this.setIssuers(baseSelector.getIssuers());
					this.setMinCRLNumber(baseSelector.getMinCRL());
					this.setMaxCRLNumber(baseSelector.getMaxCRL());
				}
			}

			public virtual bool match(CRL crl)
			{
				return (selector == null) ? (crl != null) : selector.match(crl);
			}
		}
	}

}