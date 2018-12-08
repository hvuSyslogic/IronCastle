using System;

namespace javax.crypto
{

	public class JCEUtil
	{
		public class Implementation
		{
			internal object engine;
			internal Provider provider;

			public Implementation(object engine, Provider provider)
			{
				this.engine = engine;
				this.provider = provider;
			}

			public virtual object getEngine()
			{
				return engine;
			}

			public virtual Provider getProvider()
			{
				return provider;
			}
		}

		/// <summary>
		/// see if we can find an algorithm (or its alias and what it represents) in
		/// the property table for the given provider.
		/// </summary>
		/// <returns> null if no algorithm found, an Implementation if it is. </returns>
		private static Implementation findImplementation(string baseName, string algorithm, Provider prov)
		{
			string alias;

			while (!string.ReferenceEquals((alias = prov.getProperty("Alg.Alias." + baseName + "." + algorithm)), null))
			{
				algorithm = alias;
			}

			string className = prov.getProperty(baseName + "." + algorithm);

			if (!string.ReferenceEquals(className, null))
			{
				try
				{
					Class cls;
					ClassLoader clsLoader = prov.GetType().getClassLoader();

					if (clsLoader != null)
					{
						cls = clsLoader.loadClass(className);
					}
					else
					{
						cls = Class.forName(className);
					}

					return new Implementation(cls.newInstance(), prov);
				}
				catch (ClassNotFoundException)
				{
					throw new IllegalStateException("algorithm " + algorithm + " in provider " + prov.getName() + @" but no class """ + className + @""" found!");
				}
				catch (Exception)
				{
					throw new IllegalStateException("algorithm " + algorithm + " in provider " + prov.getName() + @" but class """ + className + @""" inaccessible!");
				}
			}

			return null;
		}

		/// <summary>
		/// return an implementation for a given algorithm/provider.
		/// If the provider is null, we grab the first avalaible who has the required algorithm.
		/// </summary>
		/// <returns> null if no algorithm found, an Implementation if it is. </returns>
		/// <exception cref="NoSuchProviderException"> if a provider is specified and not found. </exception>
		internal static Implementation getImplementation(string baseName, string algorithm, string provider)
		{
			if (string.ReferenceEquals(provider, null))
			{
				Provider[] prov = Security.getProviders();

				//
				// search every provider looking for the algorithm we want.
				//
				for (int i = 0; i != prov.Length; i++)
				{
					//
					// try case insensitive
					//
					Implementation imp = findImplementation(baseName, algorithm.ToUpper(Locale.ENGLISH), prov[i]);
					if (imp != null)
					{
						return imp;
					}

					imp = findImplementation(baseName, algorithm, prov[i]);
					if (imp != null)
					{
						return imp;
					}
				}
			}
			else
			{
				Provider prov = Security.getProvider(provider);

				if (prov == null)
				{
					throw new NoSuchProviderException("Provider " + provider + " not found");
				}

				//
				// try case insensitive
				//
				Implementation imp = findImplementation(baseName, algorithm.ToUpper(Locale.ENGLISH), prov);
				if (imp != null)
				{
					return imp;
				}

				return findImplementation(baseName, algorithm, prov);
			}

			return null;
		}

		/// <summary>
		/// return an implementation for a given algorithm/provider.
		/// If the provider is null, we grab the first avalaible who has the required algorithm.
		/// </summary>
		/// <returns> null if no algorithm found, an Implementation if it is. </returns>
		/// <exception cref="NoSuchProviderException"> if a provider is specified and not found. </exception>
		internal static Implementation getImplementation(string baseName, string algorithm, Provider provider)
		{
			if (provider == null)
			{
				Provider[] prov = Security.getProviders();

				//
				// search every provider looking for the algorithm we want.
				//
				for (int i = 0; i != prov.Length; i++)
				{
					//
					// try case insensitive
					//
					Implementation imp = findImplementation(baseName, algorithm.ToUpper(Locale.ENGLISH), prov[i]);
					if (imp != null)
					{
						return imp;
					}

					imp = findImplementation(baseName, algorithm, prov[i]);
					if (imp != null)
					{
						return imp;
					}
				}
			}
			else
			{
				//
				// try case insensitive
				//
				Implementation imp = findImplementation(baseName, algorithm.ToUpper(Locale.ENGLISH), provider);
				if (imp != null)
				{
					return imp;
				}

				return findImplementation(baseName, algorithm, provider);
			}

			return null;
		}
	}

}