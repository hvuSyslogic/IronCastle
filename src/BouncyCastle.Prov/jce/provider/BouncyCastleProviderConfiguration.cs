using org.bouncycastle.jcajce.provider.config;

namespace org.bouncycastle.jce.provider
{

	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using DSAParameters = org.bouncycastle.crypto.@params.DSAParameters;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using ProviderConfiguration = org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
	using ProviderConfigurationPermission = org.bouncycastle.jcajce.provider.config.ProviderConfigurationPermission;
	using DHDomainParameterSpec = org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;

	public class BouncyCastleProviderConfiguration : ProviderConfiguration
	{
		private static Permission BC_EC_LOCAL_PERMISSION = new ProviderConfigurationPermission(BouncyCastleProvider.PROVIDER_NAME, ConfigurableProvider_Fields.THREAD_LOCAL_EC_IMPLICITLY_CA);
		private static Permission BC_EC_PERMISSION = new ProviderConfigurationPermission(BouncyCastleProvider.PROVIDER_NAME, ConfigurableProvider_Fields.EC_IMPLICITLY_CA);
		private static Permission BC_DH_LOCAL_PERMISSION = new ProviderConfigurationPermission(BouncyCastleProvider.PROVIDER_NAME, ConfigurableProvider_Fields.THREAD_LOCAL_DH_DEFAULT_PARAMS);
		private static Permission BC_DH_PERMISSION = new ProviderConfigurationPermission(BouncyCastleProvider.PROVIDER_NAME, ConfigurableProvider_Fields.DH_DEFAULT_PARAMS);
		private static Permission BC_EC_CURVE_PERMISSION = new ProviderConfigurationPermission(BouncyCastleProvider.PROVIDER_NAME, ConfigurableProvider_Fields.ACCEPTABLE_EC_CURVES);
		private static Permission BC_ADDITIONAL_EC_CURVE_PERMISSION = new ProviderConfigurationPermission(BouncyCastleProvider.PROVIDER_NAME, ConfigurableProvider_Fields.ADDITIONAL_EC_PARAMETERS);

		private ThreadLocal ecThreadSpec = new ThreadLocal();
		private ThreadLocal dhThreadSpec = new ThreadLocal();

		private volatile ECParameterSpec ecImplicitCaParams;
		private volatile object dhDefaultParams;
		private volatile Set acceptableNamedCurves = new HashSet();
		private volatile Map additionalECParameters = new HashMap();

		public virtual void setParameter(string parameterName, object parameter)
		{
			SecurityManager securityManager = System.getSecurityManager();

			if (parameterName.Equals(ConfigurableProvider_Fields.THREAD_LOCAL_EC_IMPLICITLY_CA))
			{
				ECParameterSpec curveSpec;

				if (securityManager != null)
				{
					securityManager.checkPermission(BC_EC_LOCAL_PERMISSION);
				}

				if (parameter is ECParameterSpec || parameter == null)
				{
					curveSpec = (ECParameterSpec)parameter;
				}
				else // assume java.security.spec
				{
					curveSpec = EC5Util.convertSpec((java.security.spec.ECParameterSpec)parameter, false);
				}

				if (curveSpec == null)
				{
					ecThreadSpec.remove();
				}
				else
				{
					ecThreadSpec.set(curveSpec);
				}
			}
			else if (parameterName.Equals(ConfigurableProvider_Fields.EC_IMPLICITLY_CA))
			{
				if (securityManager != null)
				{
					securityManager.checkPermission(BC_EC_PERMISSION);
				}

				if (parameter is ECParameterSpec || parameter == null)
				{
					ecImplicitCaParams = (ECParameterSpec)parameter;
				}
				else // assume java.security.spec
				{
					ecImplicitCaParams = EC5Util.convertSpec((java.security.spec.ECParameterSpec)parameter, false);
				}
			}
			else if (parameterName.Equals(ConfigurableProvider_Fields.THREAD_LOCAL_DH_DEFAULT_PARAMS))
			{
				object dhSpec;

				if (securityManager != null)
				{
					securityManager.checkPermission(BC_DH_LOCAL_PERMISSION);
				}

				if (parameter is DHParameterSpec || parameter is DHParameterSpec[] || parameter == null)
				{
					dhSpec = parameter;
				}
				else
				{
					throw new IllegalArgumentException("not a valid DHParameterSpec");
				}

				if (dhSpec == null)
				{
					dhThreadSpec.remove();
				}
				else
				{
					dhThreadSpec.set(dhSpec);
				}
			}
			else if (parameterName.Equals(ConfigurableProvider_Fields.DH_DEFAULT_PARAMS))
			{
				if (securityManager != null)
				{
					securityManager.checkPermission(BC_DH_PERMISSION);
				}

				if (parameter is DHParameterSpec || parameter is DHParameterSpec[] || parameter == null)
				{
					dhDefaultParams = parameter;
				}
				else
				{
					throw new IllegalArgumentException("not a valid DHParameterSpec or DHParameterSpec[]");
				}
			}
			else if (parameterName.Equals(ConfigurableProvider_Fields.ACCEPTABLE_EC_CURVES))
			{
				if (securityManager != null)
				{
					securityManager.checkPermission(BC_EC_CURVE_PERMISSION);
				}

				this.acceptableNamedCurves = (Set)parameter;
			}
			else if (parameterName.Equals(ConfigurableProvider_Fields.ADDITIONAL_EC_PARAMETERS))
			{
				if (securityManager != null)
				{
					securityManager.checkPermission(BC_ADDITIONAL_EC_CURVE_PERMISSION);
				}

				this.additionalECParameters = (Map)parameter;
			}
		}

		public virtual ECParameterSpec getEcImplicitlyCa()
		{
			ECParameterSpec spec = (ECParameterSpec)ecThreadSpec.get();

			if (spec != null)
			{
				return spec;
			}

			return ecImplicitCaParams;
		}

		public virtual DHParameterSpec getDHDefaultParameters(int keySize)
		{
			object @params = dhThreadSpec.get();
			if (@params == null)
			{
				@params = dhDefaultParams;
			}

			if (@params is DHParameterSpec)
			{
				DHParameterSpec spec = (DHParameterSpec)@params;

				if (spec.getP().bitLength() == keySize)
				{
					return spec;
				}
			}
			else if (@params is DHParameterSpec[])
			{
				DHParameterSpec[] specs = (DHParameterSpec[])@params;

				for (int i = 0; i != specs.Length; i++)
				{
					if (specs[i].getP().bitLength() == keySize)
					{
						return specs[i];
					}
				}
			}

			DHParameters dhParams = CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DH_DEFAULT_PARAMS, keySize);
			if (dhParams != null)
			{
				return new DHDomainParameterSpec(dhParams);
			}

			return null;
		}

		public virtual DSAParameterSpec getDSADefaultParameters(int keySize)
		{
			DSAParameters dsaParams = CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DSA_DEFAULT_PARAMS, keySize);
			if (dsaParams != null)
			{
				return new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
			}

			return null;
		}

		public virtual Set getAcceptableNamedCurves()
		{
			return Collections.unmodifiableSet(acceptableNamedCurves);
		}

		public virtual Map getAdditionalECParameters()
		{
			return Collections.unmodifiableMap(additionalECParameters);
		}
	}

}