using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.eac
{

	public class BidirectionalMap : Hashtable
	{
		private const long serialVersionUID = -7457289971962812909L;

		internal Hashtable reverseMap = new Hashtable();

		public virtual object getReverse(object o)
		{
			return reverseMap.get(o);
		}

		public virtual object put(object key, object o)
		{
			reverseMap.put(o, key);
			return base.put(key, o);
		}

	}

}