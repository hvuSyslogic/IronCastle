using System;

namespace org.bouncycastle.jce.provider
{

	using PKIXExtendedParameters = org.bouncycastle.jcajce.PKIXExtendedParameters;
	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using ExtCertPathValidatorException = org.bouncycastle.jce.exception.ExtCertPathValidatorException;
	using Selector = org.bouncycastle.util.Selector;
	using ExtendedPKIXParameters = org.bouncycastle.x509.ExtendedPKIXParameters;
	using X509AttributeCertStoreSelector = org.bouncycastle.x509.X509AttributeCertStoreSelector;
	using X509AttributeCertificate = org.bouncycastle.x509.X509AttributeCertificate;

	/// <summary>
	/// CertPathValidatorSpi implementation for X.509 Attribute Certificates la RFC 3281.
	/// </summary>
	/// <seealso cref= org.bouncycastle.x509.ExtendedPKIXParameters </seealso>
	public class PKIXAttrCertPathValidatorSpi : CertPathValidatorSpi
	{
		private readonly JcaJceHelper helper = new BCJcaJceHelper();

		public PKIXAttrCertPathValidatorSpi()
		{
		}

		/// <summary>
		/// Validates an attribute certificate with the given certificate path.
		/// 
		/// <para>
		/// <code>params</code> must be an instance of
		/// <code>ExtendedPKIXParameters</code>.
		/// </para>
		/// <para>
		/// The target constraints in the <code>params</code> must be an
		/// <code>X509AttributeCertStoreSelector</code> with at least the attribute
		/// certificate criterion set. Obey that also target informations may be
		/// necessary to correctly validate this attribute certificate.
		/// </para>
		/// <para>
		/// The attribute certificate issuer must be added to the trusted attribute
		/// issuers with <seealso cref="org.bouncycastle.x509.ExtendedPKIXParameters#setTrustedACIssuers(java.util.Set)"/>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="certPath"> The certificate path which belongs to the attribute
		///            certificate issuer public key certificate. </param>
		/// <param name="params"> The PKIX parameters. </param>
		/// <returns> A <code>PKIXCertPathValidatorResult</code> of the result of
		///         validating the <code>certPath</code>. </returns>
		/// <exception cref="java.security.InvalidAlgorithmParameterException"> if <code>params</code> is
		///             inappropriate for this validator. </exception>
		/// <exception cref="java.security.cert.CertPathValidatorException"> if the verification fails. </exception>
		public virtual CertPathValidatorResult engineValidate(CertPath certPath, CertPathParameters @params)
		{
			if (!(@params is ExtendedPKIXParameters || @params is PKIXExtendedParameters))
			{
				throw new InvalidAlgorithmParameterException("Parameters must be a " + typeof(ExtendedPKIXParameters).getName() + " instance.");
			}
			Set attrCertCheckers = new HashSet();
			Set prohibitedACAttrbiutes = new HashSet();
			Set necessaryACAttributes = new HashSet();
			Set trustedACIssuers = new HashSet();

			PKIXExtendedParameters paramsPKIX;
			if (@params is PKIXParameters)
			{
				PKIXExtendedParameters.Builder paramsPKIXBldr = new PKIXExtendedParameters.Builder((PKIXParameters)@params);

				if (@params is ExtendedPKIXParameters)
				{
					ExtendedPKIXParameters extPKIX = (ExtendedPKIXParameters)@params;

					paramsPKIXBldr.setUseDeltasEnabled(extPKIX.isUseDeltasEnabled());
					paramsPKIXBldr.setValidityModel(extPKIX.getValidityModel());
					attrCertCheckers = extPKIX.getAttrCertCheckers();
					prohibitedACAttrbiutes = extPKIX.getProhibitedACAttributes();
					necessaryACAttributes = extPKIX.getNecessaryACAttributes();
				}

				paramsPKIX = paramsPKIXBldr.build();
			}
			else
			{
				paramsPKIX = (PKIXExtendedParameters)@params;
			}

			Selector certSelect = paramsPKIX.getTargetConstraints();
			if (!(certSelect is X509AttributeCertStoreSelector))
			{
				throw new InvalidAlgorithmParameterException("TargetConstraints must be an instance of " + typeof(X509AttributeCertStoreSelector).getName() + " for " + this.GetType().getName() + " class.");
			}

			X509AttributeCertificate attrCert = ((X509AttributeCertStoreSelector) certSelect).getAttributeCert();

			CertPath holderCertPath = RFC3281CertPathUtilities.processAttrCert1(attrCert, paramsPKIX);
			CertPathValidatorResult result = RFC3281CertPathUtilities.processAttrCert2(certPath, paramsPKIX);
			X509Certificate issuerCert = (X509Certificate) certPath.getCertificates().get(0);
			RFC3281CertPathUtilities.processAttrCert3(issuerCert, paramsPKIX);
			RFC3281CertPathUtilities.processAttrCert4(issuerCert, trustedACIssuers);
			RFC3281CertPathUtilities.processAttrCert5(attrCert, paramsPKIX);
			// 6 already done in X509AttributeCertStoreSelector
			RFC3281CertPathUtilities.processAttrCert7(attrCert, certPath, holderCertPath, paramsPKIX, attrCertCheckers);
			RFC3281CertPathUtilities.additionalChecks(attrCert, prohibitedACAttrbiutes, necessaryACAttributes);
			DateTime date = null;
			try
			{
				date = CertPathValidatorUtilities.getValidCertDateFromValidityModel(paramsPKIX, null, -1);
			}
			catch (AnnotatedException e)
			{
				throw new ExtCertPathValidatorException("Could not get validity date from attribute certificate.", e);
			}
			RFC3281CertPathUtilities.checkCRLs(attrCert, paramsPKIX, issuerCert, date, certPath.getCertificates(), helper);
			return result;
		}
	}

}