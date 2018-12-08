using System;

namespace org.bouncycastle.pqc.jcajce.provider
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using ProviderConfiguration = org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

	public class BouncyCastlePQCProvider : Provider, ConfigurableProvider
	{
		private static string info = "BouncyCastle Post-Quantum Security Provider v1.61b";

		public static string PROVIDER_NAME = "BCPQC";

		public const ProviderConfiguration CONFIGURATION = null;


		private static readonly Map keyInfoConverters = new HashMap();

		/*
		* Configurable symmetric ciphers
		*/
		private const string ALGORITHM_PACKAGE = "org.bouncycastle.pqc.jcajce.provider.";
		private static readonly string[] ALGORITHMS = new string[] {"Rainbow", "McEliece", "SPHINCS", "NH", "XMSS", "QTESLA"};

		/// <summary>
		/// Construct a new provider.  This should only be required when
		/// using runtime registration of the provider using the
		/// <code>Security.addProvider()</code> mechanism.
		/// </summary>
		public BouncyCastlePQCProvider() : base(PROVIDER_NAME, 1.6050, info)
		{

			AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass(this));
		}

		public class PrivilegedActionAnonymousInnerClass : PrivilegedAction
		{
			private readonly BouncyCastlePQCProvider outerInstance;

			public PrivilegedActionAnonymousInnerClass(BouncyCastlePQCProvider outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public object run()
			{
				outerInstance.setup();
				return null;
			}
		}

		private void setup()
		{
			loadAlgorithms(ALGORITHM_PACKAGE, ALGORITHMS);
		}

		private void loadAlgorithms(string packageName, string[] names)
		{
			for (int i = 0; i != names.Length; i++)
			{
				Class clazz = loadClass(typeof(BouncyCastlePQCProvider), packageName + names[i] + "$Mappings");

				if (clazz != null)
				{
					try
					{
						((AlgorithmProvider)clazz.newInstance()).configure(this);
					}
					catch (Exception e)
					{ // this should never ever happen!!
						throw new InternalError("cannot create instance of " + packageName + names[i] + "$Mappings : " + e);
					}
				}
			}
		}

		public virtual void setParameter(string parameterName, object parameter)
		{
			lock (CONFIGURATION)
			{
				//((BouncyCastleProviderConfiguration)CONFIGURATION).setParameter(parameterName, parameter);
			}
		}

		public virtual bool hasAlgorithm(string type, string name)
		{
			return containsKey(type + "." + name) || containsKey("Alg.Alias." + type + "." + name);
		}

		public virtual void addAlgorithm(string key, string value)
		{
			if (containsKey(key))
			{
				throw new IllegalStateException("duplicate provider key (" + key + ") found");
			}

			put(key, value);
		}

		public virtual void addAlgorithm(string type, ASN1ObjectIdentifier oid, string className)
		{
			if (!containsKey(type + "." + className))
			{
				throw new IllegalStateException("primary key (" + type + "." + className + ") not found");
			}

			addAlgorithm(type + "." + oid, className);
			addAlgorithm(type + ".OID." + oid, className);
		}

		public virtual void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter)
		{
			lock (keyInfoConverters)
			{
				keyInfoConverters.put(oid, keyInfoConverter);
			}
		}

		public virtual void addAttributes(string key, Map<string, string> attributeMap)
		{
			for (Iterator it = attributeMap.keySet().iterator(); it.hasNext();)
			{
				string attributeName = (string)it.next();
				string attributeKey = key + " " + attributeName;
				if (containsKey(attributeKey))
				{
					throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
				}

				put(attributeKey, attributeMap.get(attributeName));
			}
		}

		private static AsymmetricKeyInfoConverter getAsymmetricKeyInfoConverter(ASN1ObjectIdentifier algorithm)
		{
			lock (keyInfoConverters)
			{
				return (AsymmetricKeyInfoConverter)keyInfoConverters.get(algorithm);
			}
		}

		public static PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
		{
			AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(publicKeyInfo.getAlgorithm().getAlgorithm());

			if (converter == null)
			{
				return null;
			}

			return converter.generatePublic(publicKeyInfo);
		}

		public static PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo)
		{
			AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());

			if (converter == null)
			{
				return null;
			}

			return converter.generatePrivate(privateKeyInfo);
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: static Class loadClass(Class sourceClass, final String className)
		internal static Class loadClass(Class sourceClass, string className)
		{
			try
			{
				ClassLoader loader = sourceClass.getClassLoader();
				if (loader != null)
				{
					return loader.loadClass(className);
				}
				else
				{
					return (Class)AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass2(className));
				}
			}
			catch (ClassNotFoundException)
			{
				// ignore - maybe log?
			}

			return null;
		}

		public class PrivilegedActionAnonymousInnerClass2 : PrivilegedAction
		{
			private string className;

			public PrivilegedActionAnonymousInnerClass2(string className)
			{
				this.className = className;
			}

			public object run()
			{
				try
				{
					return Class.forName(className);
				}
				catch (Exception)
				{
					// ignore - maybe log?
				}

				return null;
			}
		}
	}

}