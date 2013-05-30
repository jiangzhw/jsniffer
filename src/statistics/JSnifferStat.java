package statistics;

import java.util.*;

/**
 * @author jiangzhw2008@yeah.net
 *
 */
public class JSnifferStat {

    static ArrayList<JSnifferStatBsc> stakers = new ArrayList<JSnifferStatBsc>();

    public static void loadStatisticsTaker() {
        stakers.add(new JSnifferNetworkStat());
        stakers.add(new JSnifferTransStat());
    }

    /**
     * 
     * @return
     */
    public static List<JSnifferStatBsc> getStatisticsTakers() {
        return stakers;
    }

    public static JSnifferStatBsc getStatisticsTakerAt(int index) {
        return stakers.get(index);
    }
}
