namespace org.bouncycastle.x509
{

	public abstract class PKIXAttrCertChecker : Cloneable
	{

		/// <summary>
		/// Returns an immutable <code>Set</code> of X.509 attribute certificate
		/// extensions that this <code>PKIXAttrCertChecker</code> supports or
		/// <code>null</code> if no extensions are supported.
		/// <para>
		/// Each element of the set is a <code>String</code> representing the
		/// Object Identifier (OID) of the X.509 extension that is supported.
		/// </para>
		/// <para>
		/// All X.509 attribute certificate extensions that a
		/// <code>PKIXAttrCertChecker</code> might possibly be able to process
		/// should be included in the set.
		/// 
		/// </para>
		/// </summary>
		/// <returns> an immutable <code>Set</code> of X.509 extension OIDs (in
		///         <code>String</code> format) supported by this
		///         <code>PKIXAttrCertChecker</code>, or <code>null</code> if no
		///         extensions are supported </returns>
		public abstract Set getSupportedExtensions();

		/// <summary>
		/// Performs checks on the specified attribute certificate. Every handled
		/// extension is rmeoved from the <code>unresolvedCritExts</code>
		/// collection.
		/// </summary>
		/// <param name="attrCert"> The attribute certificate to be checked. </param>
		/// <param name="certPath"> The certificate path which belongs to the attribute
		///            certificate issuer public key certificate. </param>
		/// <param name="holderCertPath"> The certificate path which belongs to the holder
		///            certificate. </param>
		/// <param name="unresolvedCritExts"> a <code>Collection</code> of OID strings
		///            representing the current set of unresolved critical extensions </param>
		/// <exception cref="CertPathValidatorException"> if the specified attribute certificate
		///             does not pass the check. </exception>
		public abstract void check(X509AttributeCertificate attrCert, CertPath certPath, CertPath holderCertPath, Collection unresolvedCritExts);

		/// <summary>
		/// Returns a clone of this object.
		/// </summary>
		/// <returns> a copy of this <code>PKIXAttrCertChecker</code> </returns>
		public abstract object clone();
	}

}