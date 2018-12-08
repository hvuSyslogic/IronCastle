namespace org.bouncycastle.jcajce.provider.config
{

	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// A permission class to define what can be done with the ConfigurableProvider interface.
	/// <para>
	/// Available permissions are "threadLocalEcImplicitlyCa" and "ecImplicitlyCa" which allow the setting
	/// of the thread local and global ecImplicitlyCa parameters respectively.
	/// </para>
	/// <para>
	/// Examples:
	/// <ul>
	/// <li>ProviderConfigurationPermission("BC"); // enable all permissions</li>
	/// <li>ProviderConfigurationPermission("BC", "threadLocalEcImplicitlyCa"); // enable thread local only</li>
	/// <li>ProviderConfigurationPermission("BC", "ecImplicitlyCa"); // enable global setting only</li>
	/// <li>ProviderConfigurationPermission("BC", "threadLocalEcImplicitlyCa, ecImplicitlyCa"); // enable both explicitly</li>
	/// </ul>
	/// </para>
	/// <para>
	/// Note: permission checks are only enforced if a security manager is present.
	/// </para>
	/// </summary>
	public class ProviderConfigurationPermission : BasicPermission
	{
		private const int THREAD_LOCAL_EC_IMPLICITLY_CA = 0x01;
		private const int EC_IMPLICITLY_CA = 0x02;
		private const int THREAD_LOCAL_DH_DEFAULT_PARAMS = 0x04;
		private const int DH_DEFAULT_PARAMS = 0x08;
		private const int ACCEPTABLE_EC_CURVES = 0x10;
		private const int ADDITIONAL_EC_PARAMETERS = 0x20;

		private const int ALL = THREAD_LOCAL_EC_IMPLICITLY_CA | EC_IMPLICITLY_CA | THREAD_LOCAL_DH_DEFAULT_PARAMS | DH_DEFAULT_PARAMS | ACCEPTABLE_EC_CURVES | ADDITIONAL_EC_PARAMETERS;

		private const string THREAD_LOCAL_EC_IMPLICITLY_CA_STR = "threadlocalecimplicitlyca";
		private const string EC_IMPLICITLY_CA_STR = "ecimplicitlyca";
		private const string THREAD_LOCAL_DH_DEFAULT_PARAMS_STR = "threadlocaldhdefaultparams";
		private const string DH_DEFAULT_PARAMS_STR = "dhdefaultparams";
		private const string ACCEPTABLE_EC_CURVES_STR = "acceptableeccurves";
		private const string ADDITIONAL_EC_PARAMETERS_STR = "additionalecparameters";
		private const string ALL_STR = "all";

		private readonly string actions;
		private readonly int permissionMask;

		public ProviderConfigurationPermission(string name) : base(name)
		{
			this.actions = "all";
			this.permissionMask = ALL;
		}

		public ProviderConfigurationPermission(string name, string actions) : base(name, actions)
		{
			this.actions = actions;
			this.permissionMask = calculateMask(actions);
		}

		private int calculateMask(string actions)
		{
			StringTokenizer tok = new StringTokenizer(Strings.toLowerCase(actions), " ,");
			int mask = 0;

			while (tok.hasMoreTokens())
			{
				string s = tok.nextToken();

				if (s.Equals(THREAD_LOCAL_EC_IMPLICITLY_CA_STR))
				{
					mask |= THREAD_LOCAL_EC_IMPLICITLY_CA;
				}
				else if (s.Equals(EC_IMPLICITLY_CA_STR))
				{
					mask |= EC_IMPLICITLY_CA;
				}
				else if (s.Equals(THREAD_LOCAL_DH_DEFAULT_PARAMS_STR))
				{
					mask |= THREAD_LOCAL_DH_DEFAULT_PARAMS;
				}
				else if (s.Equals(DH_DEFAULT_PARAMS_STR))
				{
					mask |= DH_DEFAULT_PARAMS;
				}
				else if (s.Equals(ACCEPTABLE_EC_CURVES_STR))
				{
					mask |= ACCEPTABLE_EC_CURVES;
				}
				else if (s.Equals(ADDITIONAL_EC_PARAMETERS_STR))
				{
					mask |= ADDITIONAL_EC_PARAMETERS;
				}
				else if (s.Equals(ALL_STR))
				{
					mask |= ALL;
				}
			}

			if (mask == 0)
			{
				throw new IllegalArgumentException("unknown permissions passed to mask");
			}

			return mask;
		}

		public virtual string getActions()
		{
			return actions;
		}

		public virtual bool implies(Permission permission)
		{
			if (!(permission is ProviderConfigurationPermission))
			{
				return false;
			}

			if (!this.getName().Equals(permission.getName()))
			{
				return false;
			}

			ProviderConfigurationPermission other = (ProviderConfigurationPermission)permission;

			return (this.permissionMask & other.permissionMask) == other.permissionMask;
		}

		public override bool Equals(object obj)
		{
			if (obj == this)
			{
				return true;
			}

			if (obj is ProviderConfigurationPermission)
			{
				ProviderConfigurationPermission other = (ProviderConfigurationPermission)obj;

				return this.permissionMask == other.permissionMask && this.getName().Equals(other.getName());
			}

			return false;
		}

		public override int GetHashCode()
		{
			return this.getName().GetHashCode() + this.permissionMask;
		}
	}

}