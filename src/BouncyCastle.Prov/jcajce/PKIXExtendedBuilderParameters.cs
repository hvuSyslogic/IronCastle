namespace org.bouncycastle.jcajce
{

	/// <summary>
	/// This class contains extended parameters for PKIX certification path builders.
	/// </summary>
	/// <seealso cref= PKIXBuilderParameters </seealso>
	public class PKIXExtendedBuilderParameters : CertPathParameters
	{
		/// <summary>
		/// Builder for a PKIXExtendedBuilderParameters object.
		/// </summary>
		public class Builder
		{
			internal readonly PKIXExtendedParameters baseParameters;

			internal int maxPathLength = 5;
			internal Set<X509Certificate> excludedCerts = new HashSet<X509Certificate>();

			public Builder(PKIXBuilderParameters baseParameters)
			{
				this.baseParameters = (new PKIXExtendedParameters.Builder(baseParameters)).build();
				this.maxPathLength = baseParameters.getMaxPathLength();
			}

			public Builder(PKIXExtendedParameters baseParameters)
			{
				this.baseParameters = baseParameters;
			}

			/// <summary>
			/// Adds excluded certificates which are not used for building a
			/// certification path.
			/// <para>
			/// The given set is cloned to protect it against subsequent modifications.
			/// 
			/// </para>
			/// </summary>
			/// <param name="excludedCerts"> The excluded certificates to set. </param>
			public virtual Builder addExcludedCerts(Set<X509Certificate> excludedCerts)
			{
				this.excludedCerts.addAll(excludedCerts);

				return this;
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
			/// <seealso cref= #getMaxPathLength </seealso>
			public virtual Builder setMaxPathLength(int maxPathLength)
			{
				if (maxPathLength < -1)
				{
					throw new InvalidParameterException("The maximum path " + "length parameter can not be less than -1.");
				}
				this.maxPathLength = maxPathLength;

				return this;
			}

			public virtual PKIXExtendedBuilderParameters build()
			{
				return new PKIXExtendedBuilderParameters(this);
			}
		}

		private readonly PKIXExtendedParameters baseParameters;
		private readonly Set<X509Certificate> excludedCerts;
		private readonly int maxPathLength;

		private PKIXExtendedBuilderParameters(Builder builder)
		{
			this.baseParameters = builder.baseParameters;
			this.excludedCerts = Collections.unmodifiableSet(builder.excludedCerts);
			this.maxPathLength = builder.maxPathLength;
		}

		public virtual PKIXExtendedParameters getBaseParameters()
		{
			return baseParameters;
		}

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
			return excludedCerts;
		}

		/// <summary>
		/// Returns the value of the maximum number of intermediate non-self-issued
		/// certificates in the certification path.
		/// </summary>
		/// <returns> the maximum number of non-self-issued intermediate certificates
		///         in the certification path, or -1 if no limit exists. </returns>
		public virtual int getMaxPathLength()
		{
			return maxPathLength;
		}

		/// <returns> this object </returns>
		public virtual object clone()
		{
			return this;
		}
	}


}