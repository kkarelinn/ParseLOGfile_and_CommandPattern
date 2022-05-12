package com;

import com.query.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class LogParser implements IPQuery, UserQuery, DateQuery, EventQuery, QLQuery {
    private Path logDir;
    private List<LogEntity> logEntities = new ArrayList<>();
    private DateFormat simpleDateFormat = new SimpleDateFormat("d.M.yyyy H:m:s");

    public LogParser(Path logDir) {
        this.logDir = logDir;
        readLogs();
    }

    @Override
    public int getNumberOfUniqueIPs(Date after, Date before) {
        return getUniqueIPs(after, before).size();
    }

    @Override
    public Set<String> getUniqueIPs(Date after, Date before) {
        return dateStream(after, before)
                .map(LogEntity::getIp)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getIPsForUser(String user, Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getUser().equals(user))
                .map(LogEntity::getIp)
                .collect(Collectors.toSet());
    }

    private Stream<LogEntity> dateStream(Date after, Date before) {
        return logEntities.stream()
                .filter(e -> dateBetweenDates(e.getDate(), after, before));
    }

    @Override
    public Set<String> getIPsForEvent(Event event, Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getEvent().equals(event))
                .map(LogEntity::getIp)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getIPsForStatus(Status status, Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getStatus().equals(status))
                .map(LogEntity::getIp)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getAllUsers() {
        return logEntities.stream().map(LogEntity::getUser).collect(Collectors.toSet());
    }

    @Override
    public int getNumberOfUsers(Date after, Date before) {
        return dateStream(after, before)
                .map(LogEntity::getUser)
                .collect(Collectors.toSet()).size();
    }

    @Override
    public int getNumberOfUserEvents(String user, Date after, Date before) {
        return dateStream(after, before)
                .filter(u -> u.getUser().equals(user))
                .map(LogEntity::getEvent)
                .collect(Collectors.toSet()).size();
    }

    @Override
    public Set<String> getUsersForIP(String ip, Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getIp().equals(ip))
                .map(LogEntity::getUser)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getLoggedUsers(Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getEvent().equals(Event.LOGIN))
                .map(LogEntity::getUser)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getDownloadedPluginUsers(Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getEvent().equals(Event.DOWNLOAD_PLUGIN))
                .map(LogEntity::getUser)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getWroteMessageUsers(Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getEvent().equals(Event.WRITE_MESSAGE))
                .map(LogEntity::getUser)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getSolvedTaskUsers(Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getEvent().equals(Event.SOLVE_TASK))
                .map(LogEntity::getUser)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getSolvedTaskUsers(Date after, Date before, int task) {
        return dateStream(after, before)
                .filter(e -> e.getEvent().equals(Event.SOLVE_TASK))
                .filter(e -> e.getEventAdditionalParameter() == task)
                .map(LogEntity::getUser)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getDoneTaskUsers(Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getEvent().equals(Event.DONE_TASK))
                .map(LogEntity::getUser)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getDoneTaskUsers(Date after, Date before, int task) {
        return dateStream(after, before)
                .filter(e -> e.getEvent().equals(Event.DONE_TASK))
                .filter(e -> e.getEventAdditionalParameter() == task)
                .map(LogEntity::getUser)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Date> getDatesForUserAndEvent(String user, Event event, Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getEvent().equals(event))
                .filter(e -> e.getUser().equals(user))
                .map(LogEntity::getDate)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Date> getDatesWhenSomethingFailed(Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getStatus().equals(Status.FAILED))
                .map(LogEntity::getDate)
                .collect(Collectors.toSet());
    }


    @Override
    public Set<Date> getDatesWhenErrorHappened(Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getStatus().equals(Status.ERROR))
                .map(LogEntity::getDate)
                .collect(Collectors.toSet());
    }

    @Override
    public Date getDateWhenUserLoggedFirstTime(String user, Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getEvent().equals(Event.LOGIN))
                .filter(e -> e.getUser().equals(user))
                .map(LogEntity::getDate)
                .min(Date::compareTo)
                .orElse(null);

    }

    @Override
    public Date getDateWhenUserSolvedTask(String user, int task, Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getUser().equals(user))
                .filter(e -> e.getEvent().equals(Event.SOLVE_TASK))
                .filter(e -> e.getEventAdditionalParameter() == task)
                .map(LogEntity::getDate)
                .min(Date::compareTo)
                .orElse(null);
    }

    @Override
    public Date getDateWhenUserDoneTask(String user, int task, Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getUser().equals(user))
                .filter(e -> e.getEvent().equals(Event.DONE_TASK))
                .filter(e -> e.getEventAdditionalParameter() == task)
                .map(LogEntity::getDate)
                .min(Date::compareTo)
                .orElse(null);
    }

    @Override
    public Set<Date> getDatesWhenUserWroteMessage(String user, Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getUser().equals(user))
                .filter(e -> e.getEvent().equals(Event.WRITE_MESSAGE))
                .map(LogEntity::getDate)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Date> getDatesWhenUserDownloadedPlugin(String user, Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getUser().equals(user))
                .filter(e -> e.getEvent().equals(Event.DOWNLOAD_PLUGIN))
                .map(LogEntity::getDate)
                .collect(Collectors.toSet());
    }

    @Override
    public int getNumberOfAllEvents(Date after, Date before) {
        return getAllEvents(after, before).size();
    }

    @Override
    public Set<Event> getAllEvents(Date after, Date before) {
        return dateStream(after, before)
                .map(LogEntity::getEvent)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getEventsForIP(String ip, Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getIp().equals(ip))
                .map(LogEntity::getEvent)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getEventsForUser(String user, Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getUser().equals(user))
                .map(LogEntity::getEvent)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getFailedEvents(Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getStatus().equals(Status.FAILED))
                .map(LogEntity::getEvent)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getErrorEvents(Date after, Date before) {
        return dateStream(after, before)
                .filter(e -> e.getStatus().equals(Status.ERROR))
                .map(LogEntity::getEvent)
                .collect(Collectors.toSet());
    }

    @Override
    public int getNumberOfAttemptToSolveTask(int task, Date after, Date before) {
        return (int) dateStream(after, before)
                .filter(e -> e.getEventAdditionalParameter() == task)
                .filter(e -> e.getEvent().equals(Event.SOLVE_TASK))
                .count();
    }

    @Override
    public int getNumberOfSuccessfulAttemptToSolveTask(int task, Date after, Date before) {
        return (int) dateStream(after, before)
                .filter(e -> e.getEventAdditionalParameter() == task)
                .filter(e -> e.getEvent().equals(Event.DONE_TASK))
                .count();
    }

    @Override
    public Map<Integer, Integer> getAllSolvedTasksAndTheirNumber(Date after, Date before) {
        Map<Integer, Integer> map = new HashMap<>();
        dateStream(after, before)
                .filter(e -> e.getEvent().equals(Event.SOLVE_TASK))
                .map(LogEntity::getEventAdditionalParameter)
                .distinct()
                .forEach(t -> map.put(t, getNumberOfAttemptToSolveTask(t, after, before)));
        return map;
    }

    @Override
    public Map<Integer, Integer> getAllDoneTasksAndTheirNumber(Date after, Date before) {
        Map<Integer, Integer> map = new HashMap<>();
        dateStream(after, before)
                .filter(e -> e.getEvent().equals(Event.DONE_TASK))
                .map(LogEntity::getEventAdditionalParameter)
                .distinct()
                .forEach(t -> map.put(t, getNumberOfSuccessfulAttemptToSolveTask(t, after, before)));
        return map;
    }

    @Override
    public Set<Object> execute(String query) {
        Set<Object> result = new HashSet<>();
        String field1;
        String field2 = null;
        String value1 = null;
        Date after = null;
        Date before = null;
        Pattern pattern = Pattern.compile("get (ip|user|date|event|status)"
                + "( for (ip|user|date|event|status) = \"(.*?)\")?"
                + "( and date between \"(.*?)\" and \"(.*?)\")?");
        Matcher matcher = pattern.matcher(query);
        matcher.find();
        field1 = matcher.group(1);
        if (matcher.group(2) != null) {
            field2 = matcher.group(3);
            value1 = matcher.group(4);
            if (matcher.group(5) != null) {
                try {
                    after = simpleDateFormat.parse(matcher.group(6));
                    before = simpleDateFormat.parse(matcher.group(7));
                } catch (ParseException e) {
                }
            }
        }

        if (field2 != null && value1 != null) {
            for (int i = 0; i < logEntities.size(); i++) {
                if (dateBetweenDates(logEntities.get(i).getDate(), after, before)) {
                    if (field2.equals("date")) {
                        try {
                            if (logEntities.get(i).getDate().getTime() == simpleDateFormat.parse(value1).getTime()) {
                                result.add(getCurrentValue(logEntities.get(i), field1));
                            }
                        } catch (ParseException e) {
                        }
                    } else {
                        //"get ip for user = \"Eduard Petrovich Morozko\"
                        if (value1.equals(getCurrentValue(logEntities.get(i), field2).toString())) {
                            result.add(getCurrentValue(logEntities.get(i), field1));
                        }
                    }
                }
            }
        } else {
            for (int i = 0; i < logEntities.size(); i++) {
                result.add(getCurrentValue(logEntities.get(i), field1));
            }
        }

        return result;
    }

    private void readLogs() {
        try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(logDir)) {
            for (Path file : directoryStream) {
                if (file.toString().toLowerCase().endsWith(".log")) {
                    try (BufferedReader reader = new BufferedReader(new FileReader(file.toFile()))) {
                        String line = null;
                        while ((line = reader.readLine()) != null) {
                            String[] params = line.split("\t");

                            if (params.length != 5) {
                                continue;
                            }

                            String ip = params[0];
                            String user = params[1];
                            Date date = readDate(params[2]);
                            Event event = readEvent(params[3]);
                            int eventAdditionalParameter = -1;
                            if (event.equals(Event.SOLVE_TASK) || event.equals(Event.DONE_TASK)) {
                                eventAdditionalParameter = readAdditionalParameter(params[3]);
                            }
                            Status status = readStatus(params[4]);

                            LogEntity logEntity = new LogEntity(ip, user, date, event, eventAdditionalParameter, status);
                            logEntities.add(logEntity);
                        }
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private Date readDate(String lineToParse) {
        Date date = null;
        try {
            date = simpleDateFormat.parse(lineToParse);
        } catch (ParseException e) {
        }
        return date;
    }

    private Event readEvent(String lineToParse) {
        Event event = null;
        if (lineToParse.contains("SOLVE_TASK")) {
            event = Event.SOLVE_TASK;
        } else if (lineToParse.contains("DONE_TASK")) {
            event = Event.DONE_TASK;
        } else {
            switch (lineToParse) {
                case "LOGIN": {
                    event = Event.LOGIN;
                    break;
                }
                case "DOWNLOAD_PLUGIN": {
                    event = Event.DOWNLOAD_PLUGIN;
                    break;
                }
                case "WRITE_MESSAGE": {
                    event = Event.WRITE_MESSAGE;
                    break;
                }
            }
        }
        return event;
    }

    private int readAdditionalParameter(String lineToParse) {
        if (lineToParse.contains("SOLVE_TASK")) {
            lineToParse = lineToParse.replace("SOLVE_TASK", "").replaceAll(" ", "");
            return Integer.parseInt(lineToParse);
        } else {
            lineToParse = lineToParse.replace("DONE_TASK", "").replaceAll(" ", "");
            return Integer.parseInt(lineToParse);
        }
    }

    private Status readStatus(String lineToParse) {
        Status status = null;
        switch (lineToParse) {
            case "OK": {
                status = Status.OK;
                break;
            }
            case "FAILED": {
                status = Status.FAILED;
                break;
            }
            case "ERROR": {
                status = Status.ERROR;
                break;
            }
        }
        return status;
    }

    private boolean dateBetweenDates(Date current, Date after, Date before) {
        if (after == null) {
            after = new Date(0);
        }
        if (before == null) {
            before = new Date(Long.MAX_VALUE);
        }
        return current.after(after) && current.before(before);
    }

    private Object getCurrentValue(LogEntity logEntity, String field) {
        Object value = null;
        switch (field) {
            case "ip": {
                Command method = new GetIpCommand(logEntity);
                value = method.execute();
                break;
            }
            case "user": {
                Command method = new GetUserCommand(logEntity);
                value = method.execute();
                break;
            }
            case "date": {
                Command method = new GetDateCommand(logEntity);
                value = method.execute();
                break;
            }
            case "event": {
                Command method = new GetEventCommand(logEntity);
                value = method.execute();
                break;
            }
            case "status": {
                Command method = new GetStatusCommand(logEntity);
                value = method.execute();
                break;
            }
        }
        return value;
    }

    private class LogEntity {
        private String ip;
        private String user;
        private Date date;
        private Event event;
        private int eventAdditionalParameter;
        private Status status;

        public LogEntity(String ip, String user, Date date, Event event, int eventAdditionalParameter, Status status) {
            this.ip = ip;
            this.user = user;
            this.date = date;
            this.event = event;
            this.eventAdditionalParameter = eventAdditionalParameter;
            this.status = status;
        }

        public String getIp() {
            return ip;
        }

        public String getUser() {
            return user;
        }

        public Date getDate() {
            return date;
        }

        public Event getEvent() {
            return event;
        }

        public int getEventAdditionalParameter() {
            return eventAdditionalParameter;
        }

        public Status getStatus() {
            return status;
        }
    }

    private abstract class Command {
        protected LogEntity logEntity;

        abstract Object execute();
    }

    private class GetIpCommand extends Command {
        public GetIpCommand(LogEntity logEntity) {
            this.logEntity = logEntity;
        }

        @Override
        Object execute() {
            return logEntity.getIp();
        }
    }

    private class GetUserCommand extends Command {
        public GetUserCommand(LogEntity logEntity) {
            this.logEntity = logEntity;
        }

        @Override
        Object execute() {
            return logEntity.getUser();
        }
    }

    private class GetDateCommand extends Command {
        public GetDateCommand(LogEntity logEntity) {
            this.logEntity = logEntity;
        }

        @Override
        Object execute() {
            return logEntity.getDate();
        }
    }

    private class GetEventCommand extends Command {
        public GetEventCommand(LogEntity logEntity) {
            this.logEntity = logEntity;
        }

        @Override
        Object execute() {
            return logEntity.getEvent();
        }
    }

    private class GetStatusCommand extends Command {
        public GetStatusCommand(LogEntity logEntity) {
            this.logEntity = logEntity;
        }

        @Override
        Object execute() {
            return logEntity.getStatus();
        }
    }
}