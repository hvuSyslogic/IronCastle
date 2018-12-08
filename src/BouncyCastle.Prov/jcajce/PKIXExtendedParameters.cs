using System;

namespace org.bouncycastle.jcajce
{

	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;

	/// <summary>
	/// This class extends the PKIXParameters with a validity model parameter.
	/// </summary>
	public class PKIXExtendedParameters : CertPathParameters
	{
		/// <summary>
		/// This is the default PKIX validity model. Actually there are two variants
		/// of this: The PKIX model and the modified PKIX model. The PKIX model
		/// verifies that all involved certificates must have been valid at the
		/// current time. The modified PKIX model verifies that all involved
		/// certificates were valid at the signing time. Both are indirectly choosen
		/// with the <seealso cref="PKIXParameters#setDate(Date)"/> method, so this
		/// methods sets the Date when <em>all</em> certificates must have been
		/// valid.
		/// </summary>
		public const int PKIX_VALIDITY_MODEL = 0;

		/// <summary>
		/// This model uses the following validity model. Each certificate must have
		/// been valid at the moment where is was used. That means the end
		/// certificate must have been valid at the time the signature was done. The
		/// CA certificate which signed the end certificate must have been valid,
		/// when the end certificate was signed. The CA (or Root CA) certificate must
		/// have been valid, when the CA certificate was signed and so on. So the
		/// <seealso cref="PKIXParameters#setDate(Date)"/> method sets the time, when
		/// the <em>end certificate</em> must have been valid. It is used e.g.
		/// in the German signature law.
		/// </summary>
		public const int CHAIN_VALIDITY_MODEL = 1;

		/// <summary>
		/// Builder for a PKIXExtendedParameters object.
		/// </summary>
		public class Builder
		{
			internal readonly PKIXParameters baseParameters;
			internal readonly DateTime date;

			internal PKIXCertStoreSelector targetConstraints;
			internal List<PKIXCertStore> extraCertStores = new ArrayList<PKIXCertStore>();
			internal Map<GeneralName, PKIXCertStore> namedCertificateStoreMap = new HashMap<GeneralName, PKIXCertStore>();
			internal List<PKIXCRLStore> extraCRLStores = new ArrayList<PKIXCRLStore>();
			internal Map<GeneralName, PKIXCRLStore> namedCRLStoreMap = new HashMap<GeneralName, PKIXCRLStore>();
			internal bool revocationEnabled;
			internal int validityModel = PKIX_VALIDITY_MODEL;
			internal bool useDeltas = false;
			internal Set<TrustAnchor> trustAnchors;

			public Builder(PKIXParameters baseParameters)
			{
				this.baseParameters = (PKIXParameters)baseParameters.clone();
				CertSelector constraints = baseParameters.getTargetCertConstraints();
				if (constraints != null)
				{
					this.targetConstraints = (new PKIXCertStoreSelector.Builder(constraints)).build();
				}
				DateTime checkDate = baseParameters.getDate();
				this.date = (checkDate == null) ? DateTime.Now : checkDate;
				this.revocationEnabled = baseParameters.isRevocationEnabled();
				this.trustAnchors = baseParameters.getTrustAnchors();
			}

			public Builder(PKIXExtendedParameters baseParameters)
			{
				this.baseParameters = baseParameters.baseParameters;
				this.date = baseParameters.date;
				this.targetConstraints = baseParameters.targetConstraints;
				this.extraCertStores = new ArrayList<PKIXCertStore>(baseParameters.extraCertStores);
				this.namedCertificateStoreMap = new HashMap<GeneralName, PKIXCertStore>(baseParameters.namedCertificateStoreMap);
				this.extraCRLStores = new ArrayList<PKIXCRLStore>(baseParameters.extraCRLStores);
				this.namedCRLStoreMap = new HashMap<GeneralName, PKIXCRLStore>(baseParameters.namedCRLStoreMap);
				this.useDeltas = baseParameters.useDeltas;
				this.validityModel = baseParameters.validityModel;
				this.revocationEnabled = baseParameters.isRevocationEnabled();
				this.trustAnchors = baseParameters.getTrustAnchors();
			}

			public virtual Builder addCertificateStore(PKIXCertStore store)
			{
				extraCertStores.add(store);

				return this;
			}

			public virtual Builder addNamedCertificateStore(GeneralName issuerAltName, PKIXCertStore store)
			{
				namedCertificateStoreMap.put(issuerAltName, store);

				return this;
			}

			public virtual Builder addCRLStore(PKIXCRLStore store)
			{
				extraCRLStores.add(store);

				return this;
			}

			public virtual Builder addNamedCRLStore(GeneralName issuerAltName, PKIXCRLStore store)
			{
				namedCRLStoreMap.put(issuerAltName, store);

				return this;
			}

			public virtual Builder setTargetConstraints(PKIXCertStoreSelector selector)
			{
				targetConstraints = selector;

				return this;
			}

			/// <summary>
			/// Sets if delta CRLs should be used for checking the revocation status.
			/// </summary>
			/// <param name="useDeltas"> <code>true</code> if delta CRLs should be used. </param>
			public virtual Builder setUseDeltasEnabled(bool useDeltas)
			{
				this.useDeltas = useDeltas;

				return this;
			}

			/// <param name="validityModel"> The validity model to set. </param>
			/// <seealso cref= #CHAIN_VALIDITY_MODEL </seealso>
			/// <seealso cref= #PKIX_VALIDITY_MODEL </seealso>
			public virtual Builder setValidityModel(int validityModel)
			{
				this.validityModel = validityModel;

				return this;
			}

			/// <summary>
			/// Set the trustAnchor to be used with these parameters.
			/// </summary>
			/// <param name="trustAnchor"> the trust anchor end-entity and CRLs must be based on. </param>
			/// <returns> the current builder. </returns>
			public virtual Builder setTrustAnchor(TrustAnchor trustAnchor)
			{
				this.trustAnchors = Collections.singleton(trustAnchor);

				return this;
			}

			/// <summary>
			/// Set the set of trustAnchors to be used with these parameters.
			/// </summary>
			/// <param name="trustAnchors">  a set of trustAnchors, one of which a particular end-entity and it's associated CRLs must be based on. </param>
			/// <returns> the current builder. </returns>
			public virtual Builder setTrustAnchors(Set<TrustAnchor> trustAnchors)
			{
				this.trustAnchors = trustAnchors;

				return this;
			}

			/// <summary>
			/// Flag whether or not revocation checking is to be enabled.
			/// </summary>
			/// <param name="revocationEnabled">  true if revocation checking to be enabled, false otherwise. </param>
			public virtual void setRevocationEnabled(bool revocationEnabled)
			{
				this.revocationEnabled = revocationEnabled;
			}

			public virtual PKIXExtendedParameters build()
			{
				return new PKIXExtendedParameters(this);
			}
		}

		private readonly PKIXParameters baseParameters;
		private readonly PKIXCertStoreSelector targetConstraints;
		private readonly DateTime date;
		private readonly List<PKIXCertStore> extraCertStores;
		private readonly Map<GeneralName, PKIXCertStore> namedCertificateStoreMap;
		private readonly List<PKIXCRLStore> extraCRLStores;
		private readonly Map<GeneralName, PKIXCRLStore> namedCRLStoreMap;
		private readonly bool revocationEnabled;
		private readonly bool useDeltas;
		private readonly int validityModel;
		private readonly Set<TrustAnchor> trustAnchors;

		private PKIXExtendedParameters(Builder builder)
		{
			this.baseParameters = builder.baseParameters;
			this.date = builder.date;
			this.extraCertStores = Collections.unmodifiableList(builder.extraCertStores);
			this.namedCertificateStoreMap = Collections.unmodifiableMap(new HashMap<GeneralName, PKIXCertStore>(builder.namedCertificateStoreMap));
			this.extraCRLStores = Collections.unmodifiableList(builder.extraCRLStores);
			this.namedCRLStoreMap = Collections.unmodifiableMap(new HashMap<GeneralName, PKIXCRLStore>(builder.namedCRLStoreMap));
			this.targetConstraints = builder.targetConstraints;
			this.revocationEnabled = builder.revocationEnabled;
			this.useDeltas = builder.useDeltas;
			this.validityModel = builder.validityModel;
			this.trustAnchors = Collections.unmodifiableSet(builder.trustAnchors);
		}

		public virtual List<PKIXCertStore> getCertificateStores()
		{
			return extraCertStores;
		}


		public virtual Map<GeneralName, PKIXCertStore> getNamedCertificateStoreMap()
		{
			return namedCertificateStoreMap;
		}

		public virtual List<PKIXCRLStore> getCRLStores()
		{
			return extraCRLStores;
		}

		public virtual Map<GeneralName, PKIXCRLStore> getNamedCRLStoreMap()
		{
			return namedCRLStoreMap;
		}

		public virtual DateTime getDate()
		{
			return new DateTime(date.Ticks);
		}




		/// <summary>
		/// Defaults to <code>false</code>.
		/// </summary>
		/// <returns> Returns if delta CRLs should be used. </returns>
		public virtual bool isUseDeltasEnabled()
		{
			return useDeltas;
		}



		/// <returns> Returns the validity model. </returns>
		/// <seealso cref= #CHAIN_VALIDITY_MODEL </seealso>
		/// <seealso cref= #PKIX_VALIDITY_MODEL </seealso>
		public virtual int getValidityModel()
		{
			return validityModel;
		}

		public virtual object clone()
		{
			return this;
		}

		/// <summary>
		/// Returns the required constraints on the target certificate.
		/// The constraints are returned as an instance of
		/// <code>Selector</code>. If <code>null</code>, no constraints are
		/// defined.
		/// </summary>
		/// <returns> a <code>Selector</code> specifying the constraints on the
		///         target certificate or attribute certificate (or <code>null</code>) </returns>
		/// <seealso cref= PKIXCertStoreSelector </seealso>
		public virtual PKIXCertStoreSelector getTargetConstraints()
		{
			return targetConstraints;
		}

		public virtual Set getTrustAnchors()
		{
			return trustAnchors;
		}

		public virtual Set getInitialPolicies()
		{
			return baseParameters.getInitialPolicies();
		}

		public virtual string getSigProvider()
		{
			return baseParameters.getSigProvider();
		}

		public virtual bool isExplicitPolicyRequired()
		{
			return baseParameters.isExplicitPolicyRequired();
		}

		public virtual bool isAnyPolicyInhibited()
		{
			return baseParameters.isAnyPolicyInhibited();
		}

		public virtual bool isPolicyMappingInhibited()
		{
			return baseParameters.isPolicyMappingInhibited();
		}

		public virtual List getCertPathCheckers()
		{
			return baseParameters.getCertPathCheckers();
		}

		public virtual List<CertStore> getCertStores()
		{
			return baseParameters.getCertStores();
		}

		public virtual bool isRevocationEnabled()
		{
			return revocationEnabled;
		}

	}

}