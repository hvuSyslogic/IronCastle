using System.Threading;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.util
{

	/// <summary>
	/// Utility method for accessing system properties.
	/// </summary>
	public class Properties
	{
		private Properties()
		{

		}

		private static readonly ThreadLocal<> threadProperties = new ThreadLocal();

		/// <summary>
		/// Return whether a particular override has been set to true.
		/// </summary>
		/// <param name="propertyName"> the property name for the override. </param>
		/// <returns> true if the property is set to "true", false otherwise. </returns>
		public static bool isOverrideSet(string propertyName)
		{
			try
			{
				string p = fetchProperty(propertyName);

				if (!string.ReferenceEquals(p, null))
				{
					return "true".Equals(Strings.toLowerCase(p));
				}

				return false;
			}
			catch (AccessControlException)
			{
				return false;
			}
		}

		/// <summary>
		/// Enable the specified override property for the current thread only.
		/// </summary>
		/// <param name="propertyName"> the property name for the override. </param>
		/// <param name="enable"> true if the override should be enabled, false if it should be disabled. </param>
		/// <returns> true if the override was already set, false otherwise. </returns>
		public static bool setThreadOverride(string propertyName, bool enable)
		{
			bool isSet = isOverrideSet(propertyName);

			Map localProps = (Map)threadProperties.get();
			if (localProps == null)
			{
				localProps = new HashMap();
			}

			localProps.put(propertyName, enable ? "true" : "false");

			threadProperties.set(localProps);

			return isSet;
		}

		/// <summary>
		/// Enable the specified override property in the current thread only.
		/// </summary>
		/// <param name="propertyName"> the property name for the override. </param>
		/// <returns> true if the override set true in thread local, false otherwise. </returns>
		public static bool removeThreadOverride(string propertyName)
		{
			bool isSet = isOverrideSet(propertyName);

			Map localProps = (Map)threadProperties.get();
			if (localProps == null)
			{
				return false;
			}

			localProps.remove(propertyName);

			if (localProps.isEmpty())
			{
				threadProperties.remove();
			}
			else
			{
				threadProperties.set(localProps);
			}

			return isSet;
		}

		public static BigInteger asBigInteger(string propertyName)
		{
			string p = fetchProperty(propertyName);

			if (!string.ReferenceEquals(p, null))
			{
				return new BigInteger(p);
			}

			return null;
		}

		public static Set<string> asKeySet(string propertyName)
		{
			Set<string> set = new HashSet<string>();

			string p = fetchProperty(propertyName);

			if (!string.ReferenceEquals(p, null))
			{
				StringTokenizer sTok = new StringTokenizer(p, ",");
				while (sTok.hasMoreElements())
				{
					set.add(Strings.toLowerCase(sTok.nextToken()).Trim());
				}
			}

			return Collections.unmodifiableSet(set);
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: private static String fetchProperty(final String propertyName)
		private static string fetchProperty(string propertyName)
		{
			return (string)AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass(propertyName));
		}

		public class PrivilegedActionAnonymousInnerClass : PrivilegedAction
		{
			private string propertyName;

			public PrivilegedActionAnonymousInnerClass(string propertyName)
			{
				this.propertyName = propertyName;
			}

			public object run()
			{
				Map localProps = (Map)threadProperties.get();
				if (localProps != null)
				{
					return localProps.get(propertyName);
				}

				return System.getProperty(propertyName);
			}
		}
	}

}