using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.util
{

	/// <summary>
	/// A simple collection backed store.
	/// </summary>
	public class CollectionStore<T> : Store<T>, Iterable<T>
	{
		private Collection<T> _local;

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="collection"> - initial contents for the store, this is copied. </param>
		public CollectionStore(Collection<T> collection)
		{
			_local = new ArrayList<T>(collection);
		}

		/// <summary>
		/// Return the matches in the collection for the passed in selector.
		/// </summary>
		/// <param name="selector"> the selector to match against. </param>
		/// <returns> a possibly empty collection of matching objects. </returns>
		public virtual Collection<T> getMatches(Selector<T> selector)
		{
			if (selector == null)
			{
				return new ArrayList<T>(_local);
			}
			else
			{
				List<T> col = new ArrayList<T>();
				Iterator<T> iter = _local.iterator();

				while (iter.hasNext())
				{
					T obj = iter.next();

					if (selector.match(obj))
					{
						col.add(obj);
					}
				}

				return col;
			}
		}

		public virtual Iterator<T> iterator()
		{
			return getMatches(null).iterator();
		}
	}

}