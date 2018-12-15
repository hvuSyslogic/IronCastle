using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto
{

	/// <summary>
	/// Permissions that need to be configured if a SecurityManager is used.
	/// </summary>
	public class CryptoServicesPermission : Permission
	{
		/// <summary>
		/// Enable the setting of global configuration properties. This permission implies THREAD_LOCAL_CONFIG
		/// </summary>
		public const string GLOBAL_CONFIG = "globalConfig";

		/// <summary>
		/// Enable the setting of thread local configuration properties.
		/// </summary>
		public const string THREAD_LOCAL_CONFIG = "threadLocalConfig";

		/// <summary>
		/// Enable the setting of the default SecureRandom.
		/// </summary>
		public const string DEFAULT_RANDOM = "defaultRandomConfig";

		private readonly Set<string> actions = new HashSet<string>();

		public CryptoServicesPermission(string name) : base(name)
		{

			this.actions.add(name);
		}

		public virtual bool implies(Permission permission)
		{
			if (permission is CryptoServicesPermission)
			{
				CryptoServicesPermission other = (CryptoServicesPermission)permission;

				if (this.getName().Equals(other.getName()))
				{
					return true;
				}

				if (this.actions.containsAll(other.actions))
				{
					return true;
				}
			}

			return false;
		}

		public override bool Equals(object obj)
		{
			if (obj is CryptoServicesPermission)
			{
				CryptoServicesPermission other = (CryptoServicesPermission)obj;

				if (this.actions.Equals(other.actions))
				{
					return true;
				}
			}

			return false;
		}

		public override int GetHashCode()
		{
			return actions.GetHashCode();
		}

		public virtual string getActions()
		{
			return actions.ToString();
		}
	}

}