package com.custody.auth.service;

import java.util.List;

public interface MenuAccessService {

    List<String> getMenusByGroupName(String groupName);

    boolean hasMenuAccess(String groupName, String menuName);

}
