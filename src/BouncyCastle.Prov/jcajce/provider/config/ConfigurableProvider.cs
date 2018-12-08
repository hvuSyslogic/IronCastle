namespace org.bouncycastle.jcajce.provider.config
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

	/// <summary>
	/// Implemented by the BC provider. This allows setting of hidden parameters,
	/// such as the ImplicitCA parameters from X.962, if used.
	/// </summary>
	public interface ConfigurableProvider
	{
		/// <summary>
		/// Elliptic Curve CA parameters - thread local version
		/// </summary>

		/// <summary>
		/// Elliptic Curve CA parameters - VM wide version
		/// </summary>

		/// <summary>
		/// Diffie-Hellman Default Parameters - thread local version
		/// </summary>

		/// <summary>
		/// Diffie-Hellman Default Parameters - VM wide version
		/// </summary>

		/// <summary>
		/// A set of OBJECT IDENTIFIERs representing acceptable named curves for imported keys.
		/// </summary>

		/// <summary>
		/// A set of OBJECT IDENTIFIERs to EC Curves providing local curve name mapping.
		/// </summary>

		void setParameter(string parameterName, object parameter);

		void addAlgorithm(string key, string value);

		void addAlgorithm(string type, ASN1ObjectIdentifier oid, string className);

		bool hasAlgorithm(string type, string name);

		void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter);

		void addAttributes(string key, Map<string, string> attributeMap);
	}

	public static class ConfigurableProvider_Fields
	{
		public const string THREAD_LOCAL_EC_IMPLICITLY_CA = "threadLocalEcImplicitlyCa";
		public const string EC_IMPLICITLY_CA = "ecImplicitlyCa";
		public const string THREAD_LOCAL_DH_DEFAULT_PARAMS = "threadLocalDhDefaultParams";
		public const string DH_DEFAULT_PARAMS = "DhDefaultParams";
		public const string ACCEPTABLE_EC_CURVES = "acceptableEcCurves";
		public const string ADDITIONAL_EC_PARAMETERS = "additionalEcParameters";
	}

}