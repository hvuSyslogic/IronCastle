using System;

namespace org.bouncycastle.x509
{

	using Selector = org.bouncycastle.util.Selector;
	using Store = org.bouncycastle.util.Store;

	/// <summary>
	/// This class extends the PKIXParameters with a validity model parameter.
	/// </summary>
	/// @deprecated use PKIXExtendedParameters 
	public class ExtendedPKIXParameters : PKIXParameters
	{

		private List stores;

		private Selector selector;

		private bool additionalLocationsEnabled;

		private List additionalStores;

		private Set trustedACIssuers;

		private Set necessaryACAttributes;

		private Set prohibitedACAttributes;

		private Set attrCertCheckers;

		/// <summary>
		/// Creates an instance of <code>PKIXParameters</code> with the specified
		/// <code>Set</code> of most-trusted CAs. Each element of the set is a
		/// <seealso cref="TrustAnchor TrustAnchor"/>.
		/// <para>
		///     Note that the <code>Set</code>
		/// is copied to protect against subsequent modifications.
		/// </para>
		/// </summary>
		/// <param name="trustAnchors"> a <code>Set</code> of <code>TrustAnchor</code>s </param>
		/// <exception cref="InvalidAlgorithmParameterException"> if the specified
		///             <code>Set</code> is empty. </exception>
		/// <exception cref="NullPointerException"> if the specified <code>Set</code> is
		///             <code>null</code> </exception>
		/// <exception cref="ClassCastException"> if any of the elements in the <code>Set</code>
		///             is not of type <code>java.security.cert.TrustAnchor</code> </exception>
		public ExtendedPKIXParameters(Set trustAnchors) : base(trustAnchors)
		{
			stores = new ArrayList();
			additionalStores = new ArrayList();
			trustedACIssuers = new HashSet();
			necessaryACAttributes = new HashSet();
			prohibitedACAttributes = new HashSet();
			attrCertCheckers = new HashSet();
		}

		/// <summary>
		/// Returns an instance with the parameters of a given
		/// <code>PKIXParameters</code> object.
		/// </summary>
		/// <param name="pkixParams"> The given <code>PKIXParameters</code> </param>
		/// <returns> an extended PKIX params object </returns>
		public static ExtendedPKIXParameters getInstance(PKIXParameters pkixParams)
		{
			ExtendedPKIXParameters @params;
			try
			{
				@params = new ExtendedPKIXParameters(pkixParams.getTrustAnchors());
			}
			catch (Exception e)
			{
				// cannot happen
				throw new RuntimeException(e.Message);
			}
			@params.setParams(pkixParams);
			return @params;
		}

		/// <summary>
		/// Method to support <code>clone()</code> under J2ME.
		/// <code>super.clone()</code> does not exist and fields are not copied.
		/// </summary>
		/// <param name="params"> Parameters to set. If this are
		///            <code>ExtendedPKIXParameters</code> they are copied to. </param>
		public virtual void setParams(PKIXParameters @params)
		{
			setDate(@params.getDate());
			setCertPathCheckers(@params.getCertPathCheckers());
			setCertStores(@params.getCertStores());
			setAnyPolicyInhibited(@params.isAnyPolicyInhibited());
			setExplicitPolicyRequired(@params.isExplicitPolicyRequired());
			setPolicyMappingInhibited(@params.isPolicyMappingInhibited());
			setRevocationEnabled(@params.isRevocationEnabled());
			setInitialPolicies(@params.getInitialPolicies());
			setPolicyQualifiersRejected(@params.getPolicyQualifiersRejected());
			setSigProvider(@params.getSigProvider());
			setTargetCertConstraints(@params.getTargetCertConstraints());
			try
			{
				setTrustAnchors(@params.getTrustAnchors());
			}
			catch (Exception e)
			{
				// cannot happen
				throw new RuntimeException(e.Message);
			}
			if (@params is ExtendedPKIXParameters)
			{
				ExtendedPKIXParameters _params = (ExtendedPKIXParameters) @params;
				validityModel = _params.validityModel;
				useDeltas = _params.useDeltas;
				additionalLocationsEnabled = _params.additionalLocationsEnabled;
				selector = _params.selector == null ? null : (Selector) _params.selector.clone();
				stores = new ArrayList(_params.stores);
				additionalStores = new ArrayList(_params.additionalStores);
				trustedACIssuers = new HashSet(_params.trustedACIssuers);
				prohibitedACAttributes = new HashSet(_params.prohibitedACAttributes);
				necessaryACAttributes = new HashSet(_params.necessaryACAttributes);
				attrCertCheckers = new HashSet(_params.attrCertCheckers);
			}
		}

		/// <summary>
		/// This is the default PKIX validity model. Actually there are two variants
		/// of this: The PKIX model and the modified PKIX model. The PKIX model
		/// verifies that all involved certificates must have been valid at the
		/// current time. The modified PKIX model verifies that all involved
		/// certificates were valid at the signing time. Both are indirectly choosen
		/// with the <seealso cref="PKIXParameters#setDate(java.util.Date)"/> method, so this
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
		/// <seealso cref="PKIXParameters#setDate(java.util.Date)"/> method sets the time, when
		/// the <em>end certificate</em> must have been valid.
		/// <para>
		/// It is used e.g.
		/// in the German signature law.
		/// </para>
		/// </summary>
		public const int CHAIN_VALIDITY_MODEL = 1;

		private int validityModel = PKIX_VALIDITY_MODEL;

		private bool useDeltas = false;

		/// <summary>
		/// Defaults to <code>false</code>.
		/// </summary>
		/// <returns> Returns if delta CRLs should be used. </returns>
		public virtual bool isUseDeltasEnabled()
		{
			return useDeltas;
		}

		/// <summary>
		/// Sets if delta CRLs should be used for checking the revocation status.
		/// </summary>
		/// <param name="useDeltas"> <code>true</code> if delta CRLs should be used. </param>
		public virtual void setUseDeltasEnabled(bool useDeltas)
		{
			this.useDeltas = useDeltas;
		}

		/// <returns> Returns the validity model. </returns>
		/// <seealso cref= #CHAIN_VALIDITY_MODEL </seealso>
		/// <seealso cref= #PKIX_VALIDITY_MODEL </seealso>
		public virtual int getValidityModel()
		{
			return validityModel;
		}

		/// <summary>
		/// Sets the Java CertStore to this extended PKIX parameters.
		/// </summary>
		/// <exception cref="ClassCastException"> if an element of <code>stores</code> is not
		///             a <code>CertStore</code>. </exception>
		public virtual void setCertStores(List stores)
		{
			if (stores != null)
			{
				Iterator it = stores.iterator();
				while (it.hasNext())
				{
					addCertStore((CertStore)it.next());
				}
			}
		}

		/// <summary>
		/// Sets the Bouncy Castle Stores for finding CRLs, certificates, attribute
		/// certificates or cross certificates.
		/// <para>
		/// The <code>List</code> is cloned.
		/// 
		/// </para>
		/// </summary>
		/// <param name="stores"> A list of stores to use. </param>
		/// <seealso cref= #getStores </seealso>
		/// <exception cref="ClassCastException"> if an element of <code>stores</code> is not
		///             a <seealso cref="Store"/>. </exception>
		public virtual void setStores(List stores)
		{
			if (stores == null)
			{
				this.stores = new ArrayList();
			}
			else
			{
				for (Iterator i = stores.iterator(); i.hasNext();)
				{
					if (!(i.next() is Store))
					{
						throw new ClassCastException("All elements of list must be " + "of type org.bouncycastle.util.Store.");
					}
				}
				this.stores = new ArrayList(stores);
			}
		}

		/// <summary>
		/// Adds a Bouncy Castle <seealso cref="Store"/> to find CRLs, certificates, attribute
		/// certificates or cross certificates.
		/// <para>
		/// This method should be used to add local stores, like collection based
		/// X.509 stores, if available. Local stores should be considered first,
		/// before trying to use additional (remote) locations, because they do not
		/// need possible additional network traffic.
		/// </para>
		/// <para>
		/// If <code>store</code> is <code>null</code> it is ignored.
		/// 
		/// </para>
		/// </summary>
		/// <param name="store"> The store to add. </param>
		/// <seealso cref= #getStores </seealso>
		public virtual void addStore(Store store)
		{
			if (store != null)
			{
				stores.add(store);
			}
		}

		/// <summary>
		/// Adds an additional Bouncy Castle <seealso cref="Store"/> to find CRLs, certificates,
		/// attribute certificates or cross certificates.
		/// <para>
		/// You should not use this method. This method is used for adding additional
		/// X.509 stores, which are used to add (remote) locations, e.g. LDAP, found
		/// during X.509 object processing, e.g. in certificates or CRLs. This method
		/// is used in PKIX certification path processing.
		/// </para>
		/// <para>
		/// If <code>store</code> is <code>null</code> it is ignored.
		/// 
		/// </para>
		/// </summary>
		/// <param name="store"> The store to add. </param>
		/// <seealso cref= #getStores() </seealso>
		/// @deprecated use addStore(). 
		public virtual void addAdditionalStore(Store store)
		{
			if (store != null)
			{
				additionalStores.add(store);
			}
		}

		/// <summary>
		/// @deprecated
		/// </summary>
		public virtual void addAddionalStore(Store store)
		{
			addAdditionalStore(store);
		}

		/// <summary>
		/// Returns an immutable <code>List</code> of additional Bouncy Castle
		/// <code>Store</code>s used for finding CRLs, certificates, attribute
		/// certificates or cross certificates.
		/// </summary>
		/// <returns> an immutable <code>List</code> of additional Bouncy Castle
		///         <code>Store</code>s. Never <code>null</code>.
		/// </returns>
		/// <seealso cref= #addAdditionalStore(Store) </seealso>
		public virtual List getAdditionalStores()
		{
			return Collections.unmodifiableList(additionalStores);
		}

		/// <summary>
		/// Returns an immutable <code>List</code> of Bouncy Castle
		/// <code>Store</code>s used for finding CRLs, certificates, attribute
		/// certificates or cross certificates.
		/// </summary>
		/// <returns> an immutable <code>List</code> of Bouncy Castle
		///         <code>Store</code>s. Never <code>null</code>.
		/// </returns>
		/// <seealso cref= #setStores(List) </seealso>
		public virtual List getStores()
		{
			return Collections.unmodifiableList(new ArrayList(stores));
		}

		/// <param name="validityModel"> The validity model to set. </param>
		/// <seealso cref= #CHAIN_VALIDITY_MODEL </seealso>
		/// <seealso cref= #PKIX_VALIDITY_MODEL </seealso>
		public virtual void setValidityModel(int validityModel)
		{
			this.validityModel = validityModel;
		}

		public virtual object clone()
		{
			ExtendedPKIXParameters @params;
			try
			{
				@params = new ExtendedPKIXParameters(getTrustAnchors());
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
		/// Returns if additional <seealso cref="X509Store"/>s for locations like LDAP found
		/// in certificates or CRLs should be used.
		/// </summary>
		/// <returns> Returns <code>true</code> if additional stores are used. </returns>
		public virtual bool isAdditionalLocationsEnabled()
		{
			return additionalLocationsEnabled;
		}

		/// <summary>
		/// Sets if additional <seealso cref="X509Store"/>s for locations like LDAP found in
		/// certificates or CRLs should be used.
		/// </summary>
		/// <param name="enabled"> <code>true</code> if additional stores are used. </param>
		public virtual void setAdditionalLocationsEnabled(bool enabled)
		{
			additionalLocationsEnabled = enabled;
		}

		/// <summary>
		/// Returns the required constraints on the target certificate or attribute
		/// certificate. The constraints are returned as an instance of
		/// <code>Selector</code>. If <code>null</code>, no constraints are
		/// defined.
		/// 
		/// <para>
		/// The target certificate in a PKIX path may be a certificate or an
		/// attribute certificate.
		/// </para>
		/// <para>
		/// Note that the <code>Selector</code> returned is cloned to protect
		/// against subsequent modifications.
		/// 
		/// </para>
		/// </summary>
		/// <returns> a <code>Selector</code> specifying the constraints on the
		///         target certificate or attribute certificate (or <code>null</code>) </returns>
		/// <seealso cref= #setTargetConstraints </seealso>
		/// <seealso cref= X509CertStoreSelector </seealso>
		/// <seealso cref= X509AttributeCertStoreSelector </seealso>
		public virtual Selector getTargetConstraints()
		{
			if (selector != null)
			{
				return (Selector) selector.clone();
			}
			else
			{
				return null;
			}
		}

		/// <summary>
		/// Sets the required constraints on the target certificate or attribute
		/// certificate. The constraints are specified as an instance of
		/// <code>Selector</code>. If <code>null</code>, no constraints are
		/// defined.
		/// <para>
		/// The target certificate in a PKIX path may be a certificate or an
		/// attribute certificate.
		/// </para>
		/// <para>
		/// Note that the <code>Selector</code> specified is cloned to protect
		/// against subsequent modifications.
		/// 
		/// </para>
		/// </summary>
		/// <param name="selector"> a <code>Selector</code> specifying the constraints on
		///            the target certificate or attribute certificate (or
		///            <code>null</code>) </param>
		/// <seealso cref= #getTargetConstraints </seealso>
		/// <seealso cref= X509CertStoreSelector </seealso>
		/// <seealso cref= X509AttributeCertStoreSelector </seealso>
		public virtual void setTargetConstraints(Selector selector)
		{
			if (selector != null)
			{
				this.selector = (Selector) selector.clone();
			}
			else
			{
				this.selector = null;
			}
		}

		/// <summary>
		/// Sets the required constraints on the target certificate. The constraints
		/// are specified as an instance of <code>X509CertSelector</code>. If
		/// <code>null</code>, no constraints are defined.
		/// 
		/// <para>
		/// This method wraps the given <code>X509CertSelector</code> into a
		/// <code>X509CertStoreSelector</code>.
		/// </para>
		/// <para>
		/// Note that the <code>X509CertSelector</code> specified is cloned to
		/// protect against subsequent modifications.
		/// 
		/// </para>
		/// </summary>
		/// <param name="selector"> a <code>X509CertSelector</code> specifying the
		///            constraints on the target certificate (or <code>null</code>) </param>
		/// <seealso cref= #getTargetCertConstraints </seealso>
		/// <seealso cref= X509CertStoreSelector </seealso>
		public virtual void setTargetCertConstraints(CertSelector selector)
		{
			base.setTargetCertConstraints(selector);
			if (selector != null)
			{
				this.selector = X509CertStoreSelector.getInstance((X509CertSelector) selector);
			}
			else
			{
				this.selector = null;
			}
		}

		/// <summary>
		/// Returns the trusted attribute certificate issuers. If attribute
		/// certificates is verified the trusted AC issuers must be set.
		/// <para>
		/// The returned <code>Set</code> consists of <code>TrustAnchor</code>s.
		/// </para>
		/// <para>
		/// The returned <code>Set</code> is immutable. Never <code>null</code>
		/// 
		/// </para>
		/// </summary>
		/// <returns> Returns an immutable set of the trusted AC issuers. </returns>
		public virtual Set getTrustedACIssuers()
		{
			return Collections.unmodifiableSet(trustedACIssuers);
		}

		/// <summary>
		/// Sets the trusted attribute certificate issuers. If attribute certificates
		/// is verified the trusted AC issuers must be set.
		/// <para>
		/// The <code>trustedACIssuers</code> must be a <code>Set</code> of
		/// <code>TrustAnchor</code>
		/// </para>
		/// <para>
		/// The given set is cloned.
		/// 
		/// </para>
		/// </summary>
		/// <param name="trustedACIssuers"> The trusted AC issuers to set. Is never
		///            <code>null</code>. </param>
		/// <exception cref="ClassCastException"> if an element of <code>stores</code> is not
		///             a <code>TrustAnchor</code>. </exception>
		public virtual void setTrustedACIssuers(Set trustedACIssuers)
		{
			if (trustedACIssuers == null)
			{
				this.trustedACIssuers.clear();
				return;
			}
			for (Iterator it = trustedACIssuers.iterator(); it.hasNext();)
			{
				if (!(it.next() is TrustAnchor))
				{
					throw new ClassCastException("All elements of set must be " + "of type " + typeof(TrustAnchor).getName() + ".");
				}
			}
			this.trustedACIssuers.clear();
			this.trustedACIssuers.addAll(trustedACIssuers);
		}

		/// <summary>
		/// Returns the neccessary attributes which must be contained in an attribute
		/// certificate.
		/// <para>
		/// The returned <code>Set</code> is immutable and contains
		/// <code>String</code>s with the OIDs.
		/// 
		/// </para>
		/// </summary>
		/// <returns> Returns the necessary AC attributes. </returns>
		public virtual Set getNecessaryACAttributes()
		{
			return Collections.unmodifiableSet(necessaryACAttributes);
		}

		/// <summary>
		/// Sets the neccessary which must be contained in an attribute certificate.
		/// <para>
		/// The <code>Set</code> must contain <code>String</code>s with the
		/// OIDs.
		/// </para>
		/// <para>
		/// The set is cloned.
		/// 
		/// </para>
		/// </summary>
		/// <param name="necessaryACAttributes"> The necessary AC attributes to set. </param>
		/// <exception cref="ClassCastException"> if an element of
		///             <code>necessaryACAttributes</code> is not a
		///             <code>String</code>. </exception>
		public virtual void setNecessaryACAttributes(Set necessaryACAttributes)
		{
			if (necessaryACAttributes == null)
			{
				this.necessaryACAttributes.clear();
				return;
			}
			for (Iterator it = necessaryACAttributes.iterator(); it.hasNext();)
			{
				if (!(it.next() is string))
				{
					throw new ClassCastException("All elements of set must be " + "of type String.");
				}
			}
			this.necessaryACAttributes.clear();
			this.necessaryACAttributes.addAll(necessaryACAttributes);
		}

		/// <summary>
		/// Returns the attribute certificates which are not allowed.
		/// <para>
		/// The returned <code>Set</code> is immutable and contains
		/// <code>String</code>s with the OIDs.
		/// 
		/// </para>
		/// </summary>
		/// <returns> Returns the prohibited AC attributes. Is never <code>null</code>. </returns>
		public virtual Set getProhibitedACAttributes()
		{
			return Collections.unmodifiableSet(prohibitedACAttributes);
		}

		/// <summary>
		/// Sets the attribute certificates which are not allowed.
		/// <para>
		/// The <code>Set</code> must contain <code>String</code>s with the
		/// OIDs.
		/// </para>
		/// <para>
		/// The set is cloned.
		/// 
		/// </para>
		/// </summary>
		/// <param name="prohibitedACAttributes"> The prohibited AC attributes to set. </param>
		/// <exception cref="ClassCastException"> if an element of
		///             <code>prohibitedACAttributes</code> is not a
		///             <code>String</code>. </exception>
		public virtual void setProhibitedACAttributes(Set prohibitedACAttributes)
		{
			if (prohibitedACAttributes == null)
			{
				this.prohibitedACAttributes.clear();
				return;
			}
			for (Iterator it = prohibitedACAttributes.iterator(); it.hasNext();)
			{
				if (!(it.next() is string))
				{
					throw new ClassCastException("All elements of set must be " + "of type String.");
				}
			}
			this.prohibitedACAttributes.clear();
			this.prohibitedACAttributes.addAll(prohibitedACAttributes);
		}

		/// <summary>
		/// Returns the attribute certificate checker. The returned set contains
		/// <seealso cref="PKIXAttrCertChecker"/>s and is immutable.
		/// </summary>
		/// <returns> Returns the attribute certificate checker. Is never
		///         <code>null</code>. </returns>
		public virtual Set getAttrCertCheckers()
		{
			return Collections.unmodifiableSet(attrCertCheckers);
		}

		/// <summary>
		/// Sets the attribute certificate checkers.
		/// <para>
		/// All elements in the <code>Set</code> must a <seealso cref="PKIXAttrCertChecker"/>.
		/// </para>
		/// <para>
		/// The given set is cloned.
		/// 
		/// </para>
		/// </summary>
		/// <param name="attrCertCheckers"> The attribute certificate checkers to set. Is
		///            never <code>null</code>. </param>
		/// <exception cref="ClassCastException"> if an element of <code>attrCertCheckers</code>
		///             is not a <code>PKIXAttrCertChecker</code>. </exception>
		public virtual void setAttrCertCheckers(Set attrCertCheckers)
		{
			if (attrCertCheckers == null)
			{
				this.attrCertCheckers.clear();
				return;
			}
			for (Iterator it = attrCertCheckers.iterator(); it.hasNext();)
			{
				if (!(it.next() is PKIXAttrCertChecker))
				{
					throw new ClassCastException("All elements of set must be " + "of type " + typeof(PKIXAttrCertChecker).getName() + ".");
				}
			}
			this.attrCertCheckers.clear();
			this.attrCertCheckers.addAll(attrCertCheckers);
		}

	}

}