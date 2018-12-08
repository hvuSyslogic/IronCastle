using System;

namespace org.bouncycastle.x509
{
	using Selector = org.bouncycastle.util.Selector;


	/// <summary>
	/// This class contains extended parameters for PKIX certification path builders.
	/// </summary>
	/// <seealso cref= java.security.cert.PKIXBuilderParameters </seealso>
	/// <seealso cref= org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi </seealso>
	/// @deprecated use PKIXExtendedBuilderParameters 
	public class ExtendedPKIXBuilderParameters : ExtendedPKIXParameters
	{

		private int maxPathLength = 5;

		private Set excludedCerts = Collections.EMPTY_SET;

		/// <summary>
		/// Excluded certificates are not used for building a certification path.
		/// <para>
		/// The returned set is immutable.
		/// 
		/// </para>
		/// </summary>
		/// <returns> Returns the excluded certificates. </returns>
		public virtual Set getExcludedCerts()
		{
			return Collections.unmodifiableSet(excludedCerts);
		}

		/// <summary>
		/// Sets the excluded certificates which are not used for building a
		/// certification path. If the <code>Set</code> is <code>null</code> an
		/// empty set is assumed.
		/// <para>
		/// The given set is cloned to protect it against subsequent modifications.
		/// 
		/// </para>
		/// </summary>
		/// <param name="excludedCerts"> The excluded certificates to set. </param>
		public virtual void setExcludedCerts(Set excludedCerts)
		{
			if (excludedCerts == null)
			{
				excludedCerts = Collections.EMPTY_SET;
			}
			else
			{
				this.excludedCerts = new HashSet(excludedCerts);
			}
		}

		/// <summary>
		/// Creates an instance of <code>PKIXBuilderParameters</code> with the
		/// specified <code>Set</code> of most-trusted CAs. Each element of the set
		/// is a <seealso cref="TrustAnchor TrustAnchor"/>.
		/// 
		/// <para>
		/// Note that the <code>Set</code> is copied to protect against subsequent
		/// modifications.
		/// 
		/// </para>
		/// </summary>
		/// <param name="trustAnchors"> a <code>Set</code> of <code>TrustAnchor</code>s </param>
		/// <param name="targetConstraints"> a <code>Selector</code> specifying the
		///            constraints on the target certificate or attribute
		///            certificate. </param>
		/// <exception cref="InvalidAlgorithmParameterException"> if <code>trustAnchors</code>
		///             is empty. </exception>
		/// <exception cref="NullPointerException"> if <code>trustAnchors</code> is
		///             <code>null</code> </exception>
		/// <exception cref="ClassCastException"> if any of the elements of
		///             <code>trustAnchors</code> is not of type
		///             <code>java.security.cert.TrustAnchor</code> </exception>
		public ExtendedPKIXBuilderParameters(Set trustAnchors, Selector targetConstraints) : base(trustAnchors)
		{
			setTargetConstraints(targetConstraints);
		}

		/// <summary>
		/// Sets the maximum number of intermediate non-self-issued certificates in a
		/// certification path. The PKIX <code>CertPathBuilder</code> must not
		/// build paths longer then this length.
		/// <para>
		/// A value of 0 implies that the path can only contain a single certificate.
		/// A value of -1 does not limit the length. The default length is 5.
		/// 
		/// </para>
		/// <para>
		/// 
		/// The basic constraints extension of a CA certificate overrides this value
		/// if smaller.
		/// 
		/// </para>
		/// </summary>
		/// <param name="maxPathLength"> the maximum number of non-self-issued intermediate
		///            certificates in the certification path </param>
		/// <exception cref="InvalidParameterException"> if <code>maxPathLength</code> is set
		///             to a value less than -1
		/// </exception>
		/// <seealso cref= org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi </seealso>
		/// <seealso cref= #getMaxPathLength </seealso>
		public virtual void setMaxPathLength(int maxPathLength)
		{
			if (maxPathLength < -1)
			{
				throw new InvalidParameterException("The maximum path " + "length parameter can not be less than -1.");
			}
			this.maxPathLength = maxPathLength;
		}

		/// <summary>
		/// Returns the value of the maximum number of intermediate non-self-issued
		/// certificates in the certification path.
		/// </summary>
		/// <returns> the maximum number of non-self-issued intermediate certificates
		///         in the certification path, or -1 if no limit exists.
		/// </returns>
		/// <seealso cref= #setMaxPathLength(int) </seealso>
		public virtual int getMaxPathLength()
		{
			return maxPathLength;
		}

		/// <summary>
		/// Can alse handle <code>ExtendedPKIXBuilderParameters</code> and
		/// <code>PKIXBuilderParameters</code>.
		/// </summary>
		/// <param name="params"> Parameters to set. </param>
		/// <seealso cref= org.bouncycastle.x509.ExtendedPKIXParameters#setParams(java.security.cert.PKIXParameters) </seealso>
		public override void setParams(PKIXParameters @params)
		{
			base.setParams(@params);
			if (@params is ExtendedPKIXBuilderParameters)
			{
				ExtendedPKIXBuilderParameters _params = (ExtendedPKIXBuilderParameters) @params;
				maxPathLength = _params.maxPathLength;
				excludedCerts = new HashSet(_params.excludedCerts);
			}
			if (@params is PKIXBuilderParameters)
			{
				PKIXBuilderParameters _params = (PKIXBuilderParameters) @params;
				maxPathLength = _params.getMaxPathLength();
			}
		}

		/// <summary>
		/// Makes a copy of this <code>PKIXParameters</code> object. Changes to the
		/// copy will not affect the original and vice versa.
		/// </summary>
		/// <returns> a copy of this <code>PKIXParameters</code> object </returns>
		public override object clone()
		{
			ExtendedPKIXBuilderParameters @params = null;
			try
			{
				@params = new ExtendedPKIXBuilderParameters(getTrustAnchors(), getTargetConstraints());
			}
			catch (Exception e)
			{
				// cannot happen
				throw new RuntimeException(e.Message);
			}
			@params.setParams(this);
			return @params;
		}

		/// <summary>
		/// Returns an instance of <code>ExtendedPKIXParameters</code> which can be
		/// safely casted to <code>ExtendedPKIXBuilderParameters</code>.
		/// <para>
		/// This method can be used to get a copy from other
		/// <code>PKIXBuilderParameters</code>, <code>PKIXParameters</code>,
		/// and <code>ExtendedPKIXParameters</code> instances.
		/// 
		/// </para>
		/// </summary>
		/// <param name="pkixParams"> The PKIX parameters to create a copy of. </param>
		/// <returns> An <code>ExtendedPKIXBuilderParameters</code> instance. </returns>
		public static ExtendedPKIXParameters getInstance(PKIXParameters pkixParams)
		{
			ExtendedPKIXBuilderParameters @params;
			try
			{
				@params = new ExtendedPKIXBuilderParameters(pkixParams.getTrustAnchors(), X509CertStoreSelector.getInstance((X509CertSelector) pkixParams.getTargetCertConstraints()));
			}
			catch (Exception e)
			{
				// cannot happen
				throw new RuntimeException(e.Message);
			}
			@params.setParams(pkixParams);
			return @params;
		}
	}

}