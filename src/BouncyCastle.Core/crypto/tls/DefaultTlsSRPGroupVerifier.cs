using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	using SRP6StandardGroups = org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
	using SRP6GroupParameters = org.bouncycastle.crypto.@params.SRP6GroupParameters;

	public class DefaultTlsSRPGroupVerifier : TlsSRPGroupVerifier
	{
		protected internal static readonly Vector DEFAULT_GROUPS = new Vector();

		static DefaultTlsSRPGroupVerifier()
		{
			DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_1024);
			DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_1536);
			DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_2048);
			DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_3072);
			DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_4096);
			DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_6144);
			DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_8192);
		}

		// Vector is (SRP6GroupParameters)
		protected internal Vector groups;

		/// <summary>
		/// Accept only the group parameters specified in RFC 5054 Appendix A.
		/// </summary>
		public DefaultTlsSRPGroupVerifier() : this(DEFAULT_GROUPS)
		{
		}

		/// <summary>
		/// Specify a custom set of acceptable group parameters.
		/// </summary>
		/// <param name="groups"> a <seealso cref="Vector"/> of acceptable <seealso cref="SRP6GroupParameters"/> </param>
		public DefaultTlsSRPGroupVerifier(Vector groups)
		{
			this.groups = groups;
		}

		public virtual bool accept(SRP6GroupParameters group)
		{
			for (int i = 0; i < groups.size(); ++i)
			{
				if (areGroupsEqual(group, (SRP6GroupParameters)groups.elementAt(i)))
				{
					return true;
				}
			}
			return false;
		}

		public virtual bool areGroupsEqual(SRP6GroupParameters a, SRP6GroupParameters b)
		{
			return a == b || (areParametersEqual(a.getN(), b.getN()) && areParametersEqual(a.getG(), b.getG()));
		}

		public virtual bool areParametersEqual(BigInteger a, BigInteger b)
		{
			return a == b || a.Equals(b);
		}
	}

}