namespace org.bouncycastle.i18n.filter.test
{

	using TestCase = junit.framework.TestCase;

	public class SQLFilterTest : TestCase
	{

		private const string test1 = @"\'""=-/\;\r\n";

		public virtual void testDoFilter()
		{
			Filter filter = new SQLFilter();
			assertEquals("encode special charaters",@"\\'\""\=\-\/\\\;\r\n",filter.doFilter(test1));
		}

	}

}