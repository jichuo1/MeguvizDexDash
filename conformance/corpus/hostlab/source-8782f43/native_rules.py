"""Structural equivalent of the frozen Java auditor; no decompiler or APK parser."""
import hashlib
import json
from pathlib import Path

from native_graph import Graph, UnsupportedAudit, descriptor
from native_session import in_list

HERE = Path(__file__).resolve().parent
CATALOG = json.loads((HERE/"analysis/audit_catalog.json").read_text(encoding="utf-8"))
VIEW, ACTIVITY, LIST, STRING = "android.view.View", "android.app.Activity", "java.util.List", "java.lang.String"


def static(value): return bool(value.access & 8)
def abstract(value): return bool(value.access & 0x400)
def args(value): return list(map(str, value.args))
def j(value): return str(value).lower() if isinstance(value, bool) else str(value)
def refs(values): return ",".join(owner+"#"+method for owner, method in values) or "-"


class Rules:
    def __init__(self, session):
        source = (HERE/"analysis/HostCompatibilityAudit.java").read_text(encoding="utf-8").encode()
        if hashlib.sha256(source).hexdigest() != CATALOG["reference_sha256"]:
            raise UnsupportedAudit("Java reference changed; native rules require renewed equivalence validation")
        self.g, self.session = Graph(session), session
        self.features, self.discoveries = {}, {}
        names = CATALOG["owners"]
        self.g.prefetch(names)
        self.g.prefetch(t.raw for m in self.g.methods(self.L("auditCommentCopy.highOwners")) for t in m.args if t.raw not in {"int", "boolean", "long", "float", "double"})
        self.g.prefetch(str(m.result) for node in list(self.g.classes.values()) if node for m in node["methods"] if m.name == "newBuilder" and not m.args and static(m))

    def L(self, name): return CATALOG["lists"][name]

    def find(self, owners, predicate, inherited=False):
        return list(dict.fromkeys(m.ref for m in self.g.methods(owners, inherited=inherited) if predicate(m)))

    def has(self, owner, name):
        return any(m.name == name and not static(m) and not m.args for m in self.g.methods([owner], inherited=True))

    def emit(self, name, status, detail):
        self.features[name] = {"status": status, "detail": detail}

    def fields(self, owner):
        node = self.g.full(owner)
        return node["fields"] if node else []

    def run(self):
        g, find = self.g, self.find
        block = [m.ref for m in g.discover("tv.danmaku.bili.update.model.BiliUpgradeInfo") if not static(m) and not abstract(m)
            and str(m.result) == "tv.danmaku.bili.update.model.BiliUpgradeInfo" and args(m) == ["android.content.Context"]]
        self.emit("block_update", "FOUND" if any(o in self.L("run.blockCandidates") for o, _ in block) else "MISSING", refs(block))
        self.discoveries["block_update"] = block
        owners = self.L("run.qualityCandidates")
        semantic_ids = {(int(r["file_id"]), int(r["method_idx"])) for r in self.session.rows(
            "SELECT DISTINCT file_id,method_idx,value FROM method_strings WHERE method_class IN ("+in_list(map(descriptor, owners))+") "
            "AND (value LIKE '%quality settings:%' OR value LIKE '%pref\\_player\\_mediaSource\\_quality\\_wifi\\_key%' ESCAPE '\\') ORDER BY file_id,method_idx,value")
            if "quality settings:" in r["value"] or "pref_player_mediaSource_quality_wifi_key" in r["value"]}
        semantic = [m.ref for m in g.methods(owners) if not m.args and str(m.result) == "int" and (m.file, m.index) in semantic_ids]
        structural = find(owners, lambda m: not abstract(m) and not m.args and str(m.result) == "int" and m.name in {"a", "c", "getDefaultQuality"})
        self.emit("player_default_quality", "FOUND" if any(m in structural for m in semantic) else "PARTIAL" if structural else "MISSING",
                  "semantic="+refs(semantic)+";structural="+refs(structural))
        self.discoveries["player_default_quality"] = semantic

        low = find(self.L("auditCommentCopy.lowOwners"), lambda m: m.name in {"o0", "q0"})
        high = []
        for owner in self.L("auditCommentCopy.highOwners"):
            if not any(str(f.type).endswith(".CommentItem") for f in self.fields(owner)): continue
            high += find([owner], lambda m: not static(m) and 1 <= len(m.args) <= 5 and any(
                g.subclass(f.type.raw, VIEW) for t in m.args for f in self.fields(t.raw)))
        self.emit("comment_free_copy", "FOUND" if high else "PARTIAL" if low else "MISSING", "high="+refs(high)+";low="+refs(low))
        expandable = bool(g.get("tv.danmaku.bili.videopage.common.widget.view.ExpandableTextView") or g.get("com.mall.videodetail.vd.videopage.common.widget.view.ExpandableTextView"))
        official = find(["com.bilibili.ship.theseus.ugc.intro.ugcheadline.UgcHeadlineService$b", "com.bilibili.ship.theseus.ugc.intro.ugcheadline.UgcHeadlineService$c"],
            lambda m: m.name == "c" and args(m) == [STRING, "boolean"] or m.name in {"w", "o"} and args(m) == ["boolean", STRING])
        self.emit("description_free_copy", "FOUND" if expandable and official else "MISSING", "expandable="+j(expandable)+";official="+refs(official))
        game = find(["com.bilibili.lib.homepage.startdust.menu.a"], lambda m: not static(m) and str(m.result) == "void" and args(m) == ["android.view.Menu", "android.view.MenuInflater"])
        bases = self.L("auditHomeTopBar.baseOwners")
        base = find(bases, lambda m: m.name == "onViewCreated" and not static(m) and str(m.result) == "void" and args(m) == [VIEW, "android.os.Bundle"])
        switch = any(str(f.type).endswith(".SwitchTextView") for owner in bases for f in self.fields(owner))
        words = find(["tv.danmaku.bili.ui.main2.MainFragment", "tv.danmaku.p9138bili.p9228ui.main2.MainFragment"], lambda m: not static(m) and not abstract(m) and str(m.result) == "void" and len(m.args) == 1 and str(m.args[0]) in {"com.bilibili.app.comm.list.common.api.b", "com.bilibili.app.comm.list.common.api.d"})
        self.emit("home_top_bar", "FOUND" if base and switch and (game or words) else "PARTIAL" if game or words or base else "MISSING",
            "game="+refs(game)+";base="+refs(base)+";switch="+j(switch)+";words="+refs(words))
        fragment = "tv.danmaku.bili.ui.main2.mine.HomeUserCenterFragment"
        builds = find([fragment], lambda m: static(m) and str(m.result) == "void" and args(m) == [fragment, "tv.danmaku.bili.ui.main2.api.AccountMine"])
        list_fields = sum(not static(f) and g.subclass(f.type.raw, LIST) for f in self.fields(fragment))
        click = len(find([fragment+"$e", fragment+"$i"], lambda m: not static(m) and str(m.result) == "void" and args(m) == ["com.bilibili.lib.homepage.mine.MenuGroup$Item"])) == 1
        self.emit("mine_entry", "FOUND" if builds and list_fields == 1 and click else "MISSING", "build="+refs(builds)+";listFields="+j(list_fields)+";click="+j(click))
        manager = "tv.danmaku.bili.ui.main2.mine.modularvip.MineVipModuleManager"
        manager_fields = sum(not static(f) and g.subclass(f.type.raw, manager) for f in self.fields(fragment))
        bindings = [f for f in self.fields(manager) if not static(f) and g.subclass(str(f.type), "androidx.viewbinding.ViewBinding")]
        root = len(bindings) == 1 and any(m.name == "getRoot" and not static(m) and not m.args and g.subclass(m.result.raw, VIEW) for m in g.methods([str(bindings[0].type)], inherited=True))
        resume = len(find([fragment], lambda m: m.name == "onResume" and not static(m) and not m.args and str(m.result) == "void")) == 1
        self.emit("mine_vip", "FOUND" if manager_fields == 1 and len(bindings) == 1 and root and resume else "MISSING", "managerFields="+j(manager_fields)+";bindings="+j(len(bindings))+";root="+j(root)+";resume="+j(resume))
        getters = [m for m in g.methods(["com.bilibili.bplus.followinglist.home.mediator.MediatorFragment"]) if not static(m) and not m.args and m.result.raw == LIST]
        item, item_fields = "", False
        if len(getters) == 1 and len(getters[0].result.generic) == 1:
            item = getters[0].result.generic[0].raw
            fields = self.fields(item)
            item_fields = any(f.name == "a" and str(f.type) == STRING for f in fields) and any(f.name == "b" and str(f.type) == STRING for f in fields)
        tab = g.subclass("com.bilibili.bplus.followinglist.home.mediator.MediatorTabLayout", "com.google.android.material.tabs.TabLayout")
        self.emit("dynamic_tabs", "FOUND" if len(getters) == 1 and item_fields and tab else "MISSING", "getters="+j(len(getters))+";item="+item+";fields="+j(item_fields)+";tab="+j(tab))
        full = find(self.L("auditFullNumber.owners"), lambda m: static(m) and str(m.result) == STRING and m.name in self.L("auditFullNumber.names") and 1 <= len(m.args) <= 5 and (str(m.args[0]) in {"int", "long", "java.lang.Integer", "java.lang.Long"} or str(m.args[0]) == STRING and m.owner == "kntr.base.localization.NumberFormat_androidKt"))
        self.emit("full_number", "FOUND" if full else "MISSING", refs(full))
        portrait_owner = "com.bilibili.app.gemini.player.widget.story.GeminiPlayerFullStoryWidget"
        portrait = find([portrait_owner], lambda m: m.name == "setVisibility" and args(m) == ["int"] and str(m.result) == "void")
        self.emit("player_portrait", "FOUND" if g.subclass(portrait_owner, VIEW) and portrait else "MISSING", refs(portrait))
        activity = "com.bilibili.ship.theseus.detail.UnitedBizDetailsActivity"
        create = find([activity], lambda m: m.name == "onCreate" and not static(m) and args(m) == ["android.os.Bundle"] and str(m.result) == "void")
        self.emit("player_status_bar", "FOUND" if g.subclass(activity, ACTIVITY) and create else "MISSING", refs(create))
        holder = "com.bilibili.pegasus.PegasusHolderData"
        holder_type = any(m.name == "getHolderType" and not static(m) and not m.args and str(m.result) == STRING for m in g.methods([holder], inherited=True))
        items = find(self.L("auditHomeRecommend.responses"), lambda m: m.name == "getItems" and not static(m) and not abstract(m) and not m.args and g.subclass(m.result.raw, LIST), True)
        base = next((name for name in ["com.bilibili.pegasus.data.base.BasePegasusData", "com.bilibili.pegasus.p5730data.p5731base.BasePegasusData", holder] if g.get(name)), None)
        uri = bool(base) and any(m.name == "getUri" and not static(m) and not m.args and str(m.result) == STRING for m in g.methods([base], inherited=True))
        self.emit("home_recommend", "FOUND" if holder_type and items and uri else "MISSING", "holder="+j(holder_type)+";items="+refs(items)+";uri="+j(uri))
        lists = find(["com.bapis.bilibili.app.viewunite.v1.Relates", "com.bapis.bilibili.app.viewunite.v1.RelatesFeedReply", "com.bapis.bilibili.app.view.v1.RelatesFeedReply", "com.bapis.bilibili.app.view.v1.ViewReply", "com.bapis.bilibili.app.view.v1.PlayerRelatesReply"], lambda m: m.name in {"getCardsList", "getRelatesList"} and not static(m) and not abstract(m) and not m.args and g.subclass(m.result.raw, LIST), True)
        attributes = find(["com.bapis.bilibili.app.viewunite.common.RelateCard", "com.bapis.bilibili.app.view.v1.Relate"], lambda m: m.name in {"getCardCase", "getGoto", "getCardType"} and not static(m) and not m.args and str(m.result) != "void", True)
        self.emit("video_relate", "FOUND" if lists and attributes else "MISSING", "lists="+refs(lists)+";attributes="+refs(attributes))
        tabs = find(self.L("auditHomeTabs.owners"), lambda m: not static(m) and not abstract(m) and len(m.args) == 1 and m.args[0].raw == LIST and m.result.raw == LIST and "main2.resource." in str(m.args[0]))
        self.emit("home_tabs", "FOUND" if len(tabs) == 1 else "MISSING", refs(tabs))
        group_owners, item_owners = self.L("auditMineComponents.groupOwners"), self.L("auditMineComponents.itemOwners")
        lists = find(group_owners, lambda m: m.name == "getItemList" and not static(m) and not m.args and g.subclass(m.result.raw, LIST), True)
        titles = find(item_owners, lambda m: m.name == "getTitle" and not static(m) and not m.args and str(m.result) == STRING, True)
        legacy = any(not static(f) and not f.access & 16 and f.type.raw == LIST and len(f.type.generic) == 1 and f.type.generic[0].raw in item_owners and any(not static(t) and t.name == "title" and str(t.type) == STRING for t in self.fields(f.type.generic[0].raw)) for owner in group_owners for f in self.fields(owner))
        self.emit("mine_components", "FOUND" if lists and titles or legacy else "MISSING", "lists="+refs(lists)+";titles="+refs(titles)+";legacy="+j(legacy))
        detail = "com.bilibili.video.story.StoryDetail"
        semantics = find([detail], lambda m: m.name in self.L("auditStory.booleanNames") and not static(m) and not m.args and str(m.result) == "boolean")
        responses = find(["com.bilibili.video.story.api.StoryFeedResponse"], lambda m: m.name == "getItems" and not static(m) and not m.args and g.subclass(m.result.raw, LIST), True)
        pager = find(["com.bilibili.video.story.player.StoryPagerPlayer"], lambda m: not static(m) and not abstract(m) and str(m.result) == "void" and len(m.args) == 1 and m.args[0].raw == LIST and detail in str(m.args[0]))
        self.emit("story_purify", "FOUND" if g.get(detail) and (responses or pager) and semantics else "MISSING", "responses="+refs(responses)+";pager="+refs(pager)+";semantic="+refs(semantics))
        splash = find(self.L("auditSplash.owners"), lambda m: m.name in self.L("auditSplash.names") and not static(m) and not abstract(m) and not m.args and g.subclass(m.result.raw, LIST), True)
        self.emit("splash_ads", "FOUND" if splash else "MISSING", refs(splash))
        owners = self.L("auditBottomBar.owners")
        tabs = find(owners, lambda m: m.name == "getTabs" and not static(m) and not m.args and g.subclass(m.result.raw, LIST), True)
        binds = find(owners, lambda m: not static(m) and str(m.result) == "void" and len(m.args) == 2 and str(m.args[0]) == "int" and g.subclass(m.args[1].raw, VIEW))
        self.emit("bottom_bar", "FOUND" if len(tabs) == 1 and len(binds) == 1 else "MISSING", "tabs="+refs(tabs)+";binds="+refs(binds))
        teens = find(["com.bilibili.teenagersmode.ui.TeenagersModeDialogActivity", "com.bilibili.app.preferences.TeenagersModeDialogActivity", "com.bilibili.p4439app.preferences.TeenagersModeDialogActivity", "tv.danmaku.bili.ui.teenagersmode.TeenagersModeDialogActivity"], lambda m: m.name == "onCreate" and not static(m) and args(m) == ["android.os.Bundle"] and str(m.result) == "void")
        self.emit("teenagers_mode", "FOUND" if teens else "MISSING", refs(teens))
        self.comments()
        self.direct()
        return self.features, self.discoveries

    def comments(self):
        g, find = self.g, self.find
        reply = next((o for o in self.L("auditCommentData.replyOwners") if g.get(o)), "")
        content, member = bool(reply) and self.has(reply, "getContent"), bool(reply) and self.has(reply, "getMember")
        lists = find(["com.bapis.bilibili.main.community.reply.v1.MainListReply", "com.bapis.bilibili.p4311main.community.reply.p4312v1.MainListReply", reply], lambda m: not static(m) and not m.args and m.result.raw == LIST and reply in str(m.result), True)
        self.emit("comment_filter", "FOUND" if content and member and lists else "MISSING", "reply="+reply+";content="+j(content)+";member="+j(member)+";lists="+refs(lists))
        urls = find(["com.bapis.bilibili.main.community.reply.v1.Content", "com.bapis.bilibili.p4311main.community.reply.p4312v1.Content"], lambda m: not static(m) and not m.args and m.result.raw == LIST, True)
        optional = any(self.has(o, n) for o in ["com.bapis.bilibili.main.community.reply.v1.MainListReply", "com.bapis.bilibili.p4311main.community.reply.p4312v1.MainListReply"] for n in ["hasQoe", "getQoe", "hasOperation", "getOperation", "hasOperationV2", "getOperationV2"])
        self.emit("comment_purify", "FOUND" if urls or optional else "MISSING", "listGetters="+refs(urls)+";optional="+j(optional))
        item = "com.bilibili.app.comment3.data.model.CommentItem"
        if not reply or not g.get(item):
            self.emit("comment_topology", "MISSING", "reply="+reply+";commentItem="+j(bool(g.get(item))))
        else:
            package = reply.rsplit(".", 1)[0]
            mappers = [m.ref for m in g.discover(item) if static(m) and not abstract(m) and not m.access & 0x1000 and str(m.result) == item and m.args and str(m.args[0]) == reply]
            missing = sorted(n for n in self.L("auditCommentTopology.replyGetters") if not self.has(reply, n))
            item_id, message = self.has(item, "getId"), self.has(package+".Content", "getMessage")
            basic, offset = self.has(package+".MemberV2$Basic", "getName"), self.has("com.bapis.bilibili.pagination.FeedPaginationReply", "getNextOffset")
            root = self.has(package+".DetailListReply", "getRoot") and self.has(package+".DetailListReply", "getPaginationReply")
            def builder(owner):
                return next((str(m.result) for m in g.methods([owner]) if static(m) and m.name == "newBuilder" and not m.args), "")
            pagination_builder = builder("com.bapis.bilibili.pagination.FeedPagination")
            pagination = bool(pagination_builder) and bool(find([pagination_builder], lambda m: not static(m) and m.name == "setOffset" and args(m) == [STRING])) and self.has(pagination_builder, "build")
            detail_builder = builder(package+".DetailListReq")
            missing_setters = sorted(n for n in self.L("auditCommentTopology.detailSetters") if not detail_builder or not find([detail_builder], lambda m: not static(m) and m.name == n and len(m.args) == 1))
            detail = bool(detail_builder) and not missing_setters and self.has(detail_builder, "build")
            moss = bool(find([package+".ReplyMoss"], lambda m: not static(m) and m.name == "detailList" and len(m.args) == 2 and str(m.args[0]) == package+".DetailListReq" and str(m.result) == "void"))
            ok = not missing and item_id and message and basic and offset and root and pagination and detail and moss
            self.emit("comment_topology", "FOUND" if mappers and ok else "MISSING", "mapperOwners="+",".join(dict.fromkeys(o for o, _ in mappers))+";mappers="+refs(mappers)+";missingReplyGetters="+",".join(missing)+";itemId="+j(item_id)+";message="+j(message)+";basicName="+j(basic)+";pagination="+j(pagination)+";detail="+j(detail)+";missingDetailSetters="+",".join(missing_setters)+";moss="+j(moss)+";detailReply="+j(root)+";nextOffset="+j(offset))
            self.discoveries["comment_topology"] = mappers
        constructors, tags = [], []
        for service in self.L("auditCommentSection.services"):
            owners = list(dict.fromkeys([service]+[t.raw for m in g.methods([service]) if m.name == "<init>" for t in m.args if g.get(t.raw)]))
            for owner in owners:
                for method in g.methods([owner]):
                    if method.name != "<init>" or method.access & 0x1000: continue
                    for index, argument in enumerate(method.args):
                        if argument.raw != LIST: continue
                        types = [argument]+[f.type for f in self.fields(owner) if f.type.raw == LIST]
                        items = list(dict.fromkeys(t.generic[0].raw for t in types if len(t.generic) == 1 and t.generic[0].raw not in {"", "java.lang.Object"}))
                        for item in items:
                            for getter in g.methods([item], inherited=True):
                                enum = g.full(getter.result.raw)
                                if static(getter) or getter.args or not enum or not enum["access"] & 0x4000: continue
                                if any(static(f) and f.name.lower() == "comment" for f in enum["fields"]):
                                    constructors.append((owner, method.name+method.proto+"@"+str(index)))
                                    tags.append(getter.ref)
        constructors, tags = list(dict.fromkeys(constructors)), list(dict.fromkeys(tags))
        self.emit("comment_section", "FOUND" if constructors and len(tags) == 1 else "MISSING", "constructors="+refs(constructors)+";tags="+refs(tags))

    def direct(self):
        find, g = self.find, self.g
        requests = find(["kntr.app.ad.biz.videodetail.pausedpage.AdPausedPageApi$requestPausedPage$2", "com.bilibili.ship.theseus.united.page.pausedpage.PausedPageService$requestPausedPageData$2"], lambda m: m.name == "invokeSuspend" and not static(m) and len(m.args) == 1)
        legacy = find(["kntr.app.ad.biz.videodetail.pausedpage.ui.g"], lambda m: m.name == "invoke" and not static(m) and not m.args)
        panel = find(["com.bilibili.ship.theseus.united.page.ad.AdPanelRepository"], lambda m: m.name == "showPanel" and not static(m) and len(m.args) >= 2)
        self.emit("paused_ad", "FOUND" if requests or legacy or panel else "MISSING", "request="+refs(requests)+";legacy="+refs(legacy)+";panel="+refs(panel))
        subtype = g.subclass("com.bilibili.pegasus.holders.bannerv8.V8Banner", "com.bilibili.app.comm.list.widget.swiper.SwiperBanner")
        attach = find(["com.bilibili.app.comm.list.widget.swiper.SwiperBanner"], lambda m: m.name == "onAttachedToWindow" and not m.args, True)
        self.emit("home_banner", "FOUND" if subtype and attach else "MISSING", "subtype="+j(subtype)+";attach="+refs(attach))
        merchandise = bool(find(["com.bilibili.ship.theseus.united.page.intro.module.merchandise.MerchandiseComponent"], lambda m: m.name == "createViewEntry" and args(m) == ["android.content.Context", "android.view.ViewGroup"]))
        self.emit("merchandise", "FOUND" if merchandise else "MISSING", j(merchandise))
        body = any(self.has(o, n) for o, n in [("com.bapis.bilibili.app.viewunite.common.Mention", "getCardsList"), ("com.bilibili.biligame.videocard.GameVideoMentionCardData", "hidden"), ("com.bilibili.playerbizcommonv2.videomentioned.MentionedSectionItem", "getCards")])
        header = any(self.has(o, n) for o, n in [("com.bapis.bilibili.app.viewunite.common.Mention", "getTitle"), ("com.bapis.bilibili.app.viewunite.common.VideoMentions", "getTitle"), ("com.bilibili.playerbizcommonv2.videomentioned.MentionedSectionItem", "getHeader")])
        self.emit("game_promotion", "FOUND" if body and header else "PARTIAL" if body or header else "MISSING", "body="+j(body)+";header="+j(header))
