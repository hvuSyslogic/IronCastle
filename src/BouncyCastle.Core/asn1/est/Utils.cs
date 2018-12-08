using org.bouncycastle.Port;

namespace org.bouncycastle.asn1.est
{
	public class Utils
	{
		internal static AttrOrOID[] clone(AttrOrOID[] ids)
		{
			AttrOrOID[] tmp = new AttrOrOID[ids.Length];

			JavaSystem.arraycopy(ids, 0, tmp, 0, ids.Length);

			return tmp;
		}
	}

}